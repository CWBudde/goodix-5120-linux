# Offline driver lifecycle tests

The standalone Meson build compiles the production `goodix5120.c` as a separate translation unit. Tests call its
registered image-device vfuncs. Its protocol helpers, TLS server, send gate and image decoder are the real code.
All keys, replies and images are synthetic; this executable links no USB implementation and cannot discover devices.

## Run

```sh
meson setup /tmp/goodix-build-c libfprint/goodix5120
meson test -C /tmp/goodix-build-c --print-errorlogs
# Run one driver scenario after building:
/tmp/goodix-build-c/test-goodix5120-driver -p /goodix5120/driver/enrollment

meson setup /tmp/goodix-build-c-asan libfprint/goodix5120 -Db_sanitize=address,undefined
meson test -C /tmp/goodix-build-c-asan --print-errorlogs
```

Dependencies: GLib/GObject/GIO >= 2.68 and OpenSSL >= 3 development headers, Meson and Ninja.
Under ptrace, LeakSanitizer cannot run; use `ASAN_OPTIONS=detect_leaks=0` there and report that limitation.

## Adapter contract

`fake-libfprint/` implements only the internal API used by this driver, based on libfprint
`6f9479c3d55f847c1b3769f28ceb99227f9858cf`. SSM transitions and completion callbacks run synchronously,
including child completion that advances and frees its parent. Errors and images transfer ownership.
USB completion runs only when the test steps the pending transfer; callbacks may submit its successor.
The adapter asserts one outstanding transfer and tracks live machines. Fixture teardown requires both to be gone.

An OpenSSL memory-BIO client starts on `0xd0` and exchanges actual TLS records through framed USB replies.
Unexpected outbound opcodes fail the test. Open command order, decoded sample values and lifecycle notifications
have independent literal expectations. Timeouts advance a virtual monotonic clock instead of sleeping.

Enrollment processing completion is separately controllable. Intermediate stages require processing and lift;
the final processing completion deactivates immediately. Tests cover both orders and completion after cancellation.
Sweeps inject unplug at every open transfer and unplug, I/O failure or deactivation at all ten operation transfers
with a two-piece image. State-entry hooks also cancel both FDT states in each direction and all three capture states.

Init regressions inject empty, truncated and oversized data at every init exchange, including both firmware/reset
replies and the final MCU state. They change each documented status/header byte, chip ID and TLS-connected bit,
then assert failed open with no further OUT submission. Firmware permits exactly the supported name with an optional
NUL; hidden suffixes are rejected. Positive cases vary synthetic hashes, OTP, MCU counters and the unexplained PSK
trailing byte to keep undocumented fields opaque.

Session-failure regressions cover invalid image layout, timeout/read-budget exhaustion, malformed TLS records,
corrupt ciphertext, OUT/IN errors and I/O failure during deactivation. Repeated activation must fail without
a USB submission or handshake; late capture/FDT transitions cannot consume a queued synthetic encrypted image.
Close/reopen with a healthy fake EC restores operation. Cancellation of FDT waiting or capture remains reusable
without a new handshake.

Capture-budget regressions complete a TLS record on the fourth additional read, validate the decoded image,
and reject a wrong layout after decrypting on that same boundary. Six-fragment images still exhaust the budget
with the final fragment unread. FDT retries get eight fresh rearms after cancellation/reactivation or failed
operation/close/reopen; the existing exhaustion case guards the limit within one operation.

The USB adapter models a previously bound kernel driver and GUsb's detach-before-claim / release-before-attach
ordering, based on [GUsb 0.4.9](https://github.com/hughsie/libgusb/blob/0.4.9/gusb/gusb-device.c#L1602).
Tests require matching binding flags on close and rollback, and no release before successful claim. Injected
release and attachment failures preserve errors and block reopening that device object without new USB work.
These checks exercise the driver's GUsb calls; they do not run actual detach/attach operations.
The driver suite contains 126 subtests; the helper suites add 43.

## Limits and next regression targets

This adapter does not run libfprint's action framework, GUsb, libusb, Pixman or NBIS. Fake resizing preserves ownership
and dimensions using nearest-neighbour sampling; production uses Pixman bilinear interpolation. It cannot validate
enrollment quality, matching, timing, suspend or EC recovery.

The remaining Phase 6b task requires shared independent protocol fixtures. Failed sessions require close/reopen;
the fake EC does not establish that reopening recovers real hardware. GUsb may detach a kernel driver before an
unsuccessful claim, and its public API does not expose a separate attachment operation to undo that case.
An ambiguous release failure requires recreating the device object; that alone does not guarantee kernel-driver
restoration. Keep the first hardware-run gate in `PLAN.md`.
