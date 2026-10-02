# Offline driver lifecycle tests

The standalone Meson build compiles the production `goodix5120.c` as a separate translation unit. Tests start
libfprint actions (open, close, enroll, verify, identify, capture, cancel) through its registered device vfuncs, as
libfprint's core does. Its protocol helpers, TLS server, send gate, image decoder and template format
(`goodix5120_match.c`) are the real code; only the SIGFM view backend is a fake (`fake-matcher.c`).
All keys, replies and images are synthetic; this executable links no USB implementation and cannot discover devices.

## Run

```sh
meson setup /tmp/goodix-build-c libfprint/goodix5120
meson test -C /tmp/goodix-build-c --print-errorlogs
# Run one driver scenario after building:
/tmp/goodix-build-c/test-goodix5120-driver -p /goodix5120/driver/enroll/complete

meson setup /tmp/goodix-build-c-asan libfprint/goodix5120 -Db_sanitize=address,undefined
meson test -C /tmp/goodix-build-c-asan --print-errorlogs
```

Dependencies: GLib/GObject/GIO >= 2.68 and OpenSSL >= 3 development headers, Meson and Ninja. With OpenCV 4
development files and a C++17 compiler, `test-goodix5120-sigfm` is built too (the offline container
`goodix-offline-build-opencv:26.04` has both); without them it is skipped.
Under ptrace, LeakSanitizer cannot run; use `ASAN_OPTIONS=detect_leaks=0` there and report that limitation.

## Adapter contract

`fake-libfprint/` implements only the internal API used by this driver, based on libfprint
`6f9479c3d55f847c1b3769f28ceb99227f9858cf`. It holds one current action at a time with its own cancellable, as
libfprint's core does, and asserts upstream's completion rules: a completion matches the current action, retry
errors go only to progress/report calls, verify and identify report before they complete, and an enrolled print has
a type. SSM transitions and completion callbacks run synchronously,
including child completion that advances and frees its parent. Errors, images and prints transfer ownership.
USB completion runs only when the test steps the pending transfer; callbacks may submit its successor.
The adapter asserts one outstanding transfer and tracks live machines. Fixture teardown requires both to be gone.

An OpenSSL memory-BIO client starts on `0xd0` and exchanges actual TLS records through framed USB replies.
Unexpected outbound opcodes fail the test. Open command order, decoded sample values and lifecycle notifications
have independent literal expectations. Timeouts advance a virtual monotonic clock instead of sleeping.
The peer assembles completed OUT submissions by the outer wire length before decoding a frame;
the raw submission history remains available separately. A strict init test requires each OUT
submission to be exactly 64 bytes, matching the Go reference. Sixteen failure cases cover short,
zero-byte, I/O-error and cancelled completion at each packet of the four-packet config write.
An aggregate-deadline case requires a shrinking timeout and forbids the next packet after expiry.
Pinned libfprint's `short_is_error` excludes zero completions, so the driver checks their length itself;
the fake preserves that upstream behavior rather than concealing the production guard.

Enroll runs all 15 stages in one session, each a full touch (arm, image, lift), and stores 15 views that the real
template parser reads back; the fake records which pixels SIGFM was given (the stretched 192 x 240 image). A touch
with too few keypoints or a failed extraction is a retry stage. Verify and identify match, miss and retry; malformed
stored templates (six shapes, for verify and inside an identify gallery) fail the action before any USB submission
and leave the session usable. Sweeps inject unplug at every open transfer and unplug, I/O failure or cancellation
at all ten capture transfers with a two-piece image; after a cancellation the next action needs no handshake.
State-entry hooks also cancel both FDT states in each direction and all three capture states, during an enroll.

Init regressions inject empty, truncated and oversized data at every init exchange, including both firmware/reset
replies and the final MCU state. They change each documented status/header byte, chip ID and invalid MCU statuses,
then assert failed open with no further OUT submission. Firmware permits exactly the supported name with an optional
NUL; hidden suffixes are rejected. Positive cases vary synthetic hashes, OTP and MCU counters to keep
undocumented fields opaque. The PSK reply requires Run 8's nine-byte envelope plus a 32-byte synthetic hash;
dedicated regressions accept that recorded shape and reject the old request-echo fixture.
Run 26's literal immediate MCU status `0x00` is accepted only after authenticated TLS and a positive
`0xd4` ACK, then exercised through encrypted capture, lift and close. Separate cases reject bit-clear
statuses `0x08`, `0x01`, `0x10`, `0x11` and a negative `0xd4` ACK without further writes. Status `0x00`
does not change the TLS-bit decoder or establish when that bit will become set.

Session-failure regressions cover invalid image layout, timeout/read-budget exhaustion, malformed TLS records,
corrupt ciphertext, OUT/IN errors and I/O failure while cancelling (reported as the cancellation). Any later action
must fail without a USB submission or handshake, and cannot consume a queued synthetic encrypted image.
Close/reopen with a healthy fake EC restores operation. Cancellation of FDT waiting or capture remains reusable
without a new handshake.

Capture-budget regressions complete a TLS record on the fourth additional read, validate the decoded image,
and reject a wrong layout after decrypting on that same boundary. Six-fragment images still exhaust the budget
with the final fragment unread. FDT retries get eight fresh rearms in a new action after cancellation or after a failed
operation/close/reopen; the existing exhaustion case guards the limit within one operation.

The USB adapter models a previously bound kernel driver and GUsb's detach-before-claim / release-before-attach
ordering, based on [GUsb 0.4.9](https://github.com/hughsie/libgusb/blob/0.4.9/gusb/gusb-device.c#L1602).
Tests require matching binding flags on close and rollback, and no release before successful claim. Injected
release and attachment failures preserve errors and block reopening that device object without new USB work.
These checks exercise the driver's GUsb calls; they do not run actual detach/attach operations.
Handshake-pacing regressions require an IN interval between ServerHello and ServerHelloDone, normal reads
after that flight, the same interval between ChangeCipherSpec and Finished, and a 10 ms settle read
before `0xd4` (Run 31). An encrypted close_notify in the settle window fails open with no `0xd4`.
After the `0xd4` ACK, `0xae` waits for a 5 s listen-only read that a stale event neither shortens
nor restarts; a TLS record in that window fails open with no further `0xae` (Runs 28/29).
Immediate alerts stop further output. Further cases measure elapsed virtual time
across stale ACK/FDT/zero reads, deliver an alert at all six splits with its suffix after the interval,
expire the total budget in the first flight's interval and the settle window, complete the first
ServerHello packet at its deadline, and exhaust the budget during allocation before the first OUT submission.
Noise cannot shorten/restart the interval; fragments cannot bypass alert handling; no further write or
successful open may follow budget exhaustion. These exercise the driver, not the EC's firmware timing.

The driver suite contains 187 subtests; the protocol and TLS helpers add 46. Shared protocol checks add 39,
corpus-reader checks add two, and the template format adds four (278 total). With OpenCV, the real SIGFM backend
adds two: extraction, and that storing views changes no score (280).

## Shared independent fixtures

[The protocol corpus](../../../internal/testfixtures/testdata/README.md) pins every byte of all 14 init requests,
including the entire 224-byte config, reply expectations and secret classifications. The additional health check
and Go capture catalogue are covered too. A lifecycle scenario checks all 15 submitted open commands and answers
from the corpus, while the synthetic OpenSSL client performs the real handshake. Existing malformed-reply cases
use corpus data as their valid starting point and still require no later OUT submission after rejection.

Both languages consume the same literal FDT arms, events and event-to-arm pairs, including Run 22, saturation,
uncovered zones and both deltas. Synthetic image vectors check every 12-bit sample and grayscale pixel in bare
and wrapped layouts, geometry, trimming offsets and adjacent invalid lengths, through the shared `>> 4` mapping.
The driver's per-frame contrast stretch is C-only: hand-computed vectors cover rounding, percentile clipping of a
dead and a hot pixel, and the flat-frame fallback, and the driver scenarios expect the stretched pixels.
Expected values never come from production builders. Go FDT integration tests live in `internal/testfixtures` to preserve the protocol package's
standard-library-only import rule.

Readers fail on missing/duplicate/incomplete records and malformed values. The C fixture path is configured by
Meson, so the standalone test build requires the full repository checkout. Go embeds the same file only in test
utilities; it is absent from shipped command dependencies.

## Limits and next regression targets

This adapter does not run libfprint's action framework, GUsb, libusb or Pixman. Fake resizing preserves ownership
and dimensions using nearest-neighbour sampling; production uses Pixman bilinear interpolation. The fake matcher
scores identical images high and all others 0. Nothing here validates matching accuracy (Runs 38-40 measured SIGFM
on the sensor), timing, suspend or EC recovery.
Packet assembly models the wire contract, not the EC firmware's receive buffers or scheduling;
passing packet tests does not establish why the real EC sent Run 24's TLS `decode_error`.

Phase 6b offline coverage includes shared independent fixtures. Failed sessions require close/reopen;
the fake EC does not establish that reopening recovers real hardware. GUsb may detach a kernel driver before an
unsuccessful claim, and its public API does not expose a separate attachment operation to undo that case.
An ambiguous release failure requires recreating the device object; that alone does not guarantee kernel-driver
restoration. Follow the owner-only first-capture procedure in `PLAN.md`; hardware evidence is still required.
