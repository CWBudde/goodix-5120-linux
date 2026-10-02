# goodix5120: libfprint driver for the Goodix `27c6:5120` behind an ITE EC

This is PLAN.md Phase 6, layer 2: a libfprint image driver in C for the fingerprint reader in the Huawei MateBook
`HVY-WXX9`. The Go code in this repository is the reference, and this driver follows its command sequence.

**Status: the driver compiles inside a libfprint tree and passes offline lifecycle tests. Run 23's `0xe4` check
is corrected; Runs 24 and 25 passed the full init but the EC rejected the first TLS server flight with
`decode_error`. Both keyboards survived. Completed 64-byte OUT writes did not resolve the rejection;
a successful capture remains pending. The original pacing bundle also crashed the EC; its final error
is unavailable. Run 26's reviewed `2b77542` bundle completed authenticated TLS with 60 ms host-record
intervals, then stopped at an overly strict immediate MCU-state gate. Both keyboards worked.
The corrected gate accepts the observed status `0x00` after authentication and positive `0xd4` ACK;
Run 27 then reached the touch, but `0x20` drew no image and the TLS bit stayed clear; the final
flight and `0xd4` follow the Go timing, which Runs 28/29 showed was not enough. The current source
also listens 5 s after the `0xd4` ACK before `0xae` and paces every pair of host records; Run 33 confirmed
that pacing is what lets `0x20` answer (an unpaced final flight from the same EC state drew nothing). Run 32 drew and
decrypted the first C image, but NBIS found no minutiae in its `>> 4` frame; the current source stretches each
frame's contrast instead (257 offline tests). Run 34 ran that build from a bit-clear EC: the first
complete C capture, with the stretched frame passing minutiae detection and saved. Run 35 enrolled a
finger with libfprint's `enroll` example (5/5 stages, one retry, in one session). Run 36's verify
scored 0 on every attempt, and Run 37 measured at most 5 minutiae per frame at any scale. NBIS needs 10,
so matching needs a different matcher.**
The successful live Go runs used its historical OpenSSL subprocess; the current in-process Go endpoint
has offline evidence. Its protocol evidence comes from the Go reference,
from Runs 8, 18 and 20–22 in
[`docs/protocol.md`](../../docs/protocol.md), and from the vendor's capture and debug log. The Go probe has run this
driver's whole wire sequence live, including the capture loop three times in one TLS session (Run 22), and
`/goodix5120/fdt/run22-session` checks that this driver derives the same arms from the same events. The corrected
capture attempt remains gated on investigation and review, following the procedure below.

## Read this first: the hardware can be wedged

The sensor sits behind the ITE embedded controller that also drives the internal keyboard. A wrong frame has wedged
that EC and killed the keyboard until a cold power cycle, several times (see [`FINDINGS.md`](../../FINDINGS.md)). The
driver is built around that:

- **One way to build a command frame.** `g5120_command_frame()` refuses any opcode that is not in the send table and
  any payload whose length differs from the vendor's. An argument-less `0xe4` wedged the EC three times, and
  `/goodix5120/gate/refuses-empty-e4` pins that it cannot be built.
- **No destructive opcodes.** `0xe0` (`preset_psk_write`) and `0xf0` (`write_firmware`) are not in the send table and
  not in the source. `/goodix5120/gate/no-destructive-opcodes` checks this.
- **Health check first.** Open sends `0xa8` and requires an answer before anything else goes out, as
  `checkECResponsive` does in the Go probe. An EC left inside an unfinished TLS handshake answers nothing but
  `0xae`, and sending the init into that state cost the keyboard in Run 12.
- **Only the tested firmware.** If the firmware string is not `GF_ITE_EC_20063`, open stops before the init.
- **Everything that can fail offline fails before the first byte.** A missing or malformed PSK file, or an OpenSSL
  whose effective policy forbids suite `0x00ae`, fails open before the USB interface is claimed. Policy is
  tested on a disposable TLS server with a synthetic ClientHello; no automatic security-level downgrade occurs. An unfinished handshake leaves the EC
  stuck, so a handshake that cannot succeed must never start.
- **Fail closed.** A missing ACK or data reply, data that arrives before its ACK, an ACK status other than `0x01`,
  a handshake without progress for 5 s: each of these stops the sequence. Nothing is retried.
- **Half duplex.** Only one state machine talks to the device at a time, and nothing is written while a reply is
  awaited.
- **Completed 64-byte writes.** Each padded frame is sent one packet at a time, with the next packet submitted
  after completion. Short/zero completions stop the frame; all packets share its original write budget.
- **Experimental TLS pacing.** Between every pair of host TLS records (ServerHello/ServerHelloDone and
  ChangeCipherSpec/Finished), a 60 ms interval permits alert reads. Stale input preserves the deadline;
  fragmented TLS input is completed before more output. A 10 ms settle read precedes `0xd4`; a record
  arriving after the local handshake completed fails open. The total handshake budget bounds all states
  and transfers. Every failing run had one pair of host writes within ~1 ms (Runs 24/25 the first flight,
  26/27 Finished/`0xd4`, 28–30 ChangeCipherSpec/Finished); Go's working Run 31 never went below ~2.5 ms.
- **Listen after `0xd4`.** After the `0xd4` ACK the driver reads IN for 5 s and sends nothing, as Go's
  `collect` did after `0xd4` in Run 18, whose session set the TLS bit; C sent `0xae` 1 ms after the ACK.
  A stale event does not end the window; a TLS record in it fails open. The causal role of any of these
  timings remains unknown.
- **Immediate MCU state.** After authenticated TLS, completed host records and a positive `0xd4` ACK,
  the final reply must be 20 bytes and have the TLS bit set or exactly status `0x00` (Run 26).
  This exception does not reinterpret the clear bit. Other bit-clear states, including stuck `0x08`, stop open.
- **No USB reset.** `goodixmoc` resets its device on open; this driver does not, because what a reset does to the EC
  is unknown.
- **Driver-level redaction:** the driver withholds the PSK, `0xe4`/`0xa6` reply bodies, TLS bodies, and image data.
  TLS records are logged by type and length only. This does not cover libfprint USB transfer tracing: when
  `FP_DEBUG_TRANSFER` and debug logging are enabled, the USB helper can dump raw sensitive replies.
  Leave `FP_DEBUG_TRANSFER` unset, including inherited service environments; never publish raw transfer traces.

## Files

| File | What it is |
|---|---|
| `goodix5120.c`, `goodix5120.h` | The libfprint driver: `FpImageDevice`, `FpiSsm` state machines, USB |
| `goodix5120_proto.c/.h` | Pure framing, the send gate, the vendor sequence, TLS record splitting, FDT arm/event codec and threshold rules, 12-bit unpacking. GLib only |
| `goodix5120_tls.c/.h` | TLS 1.2 PSK server on OpenSSL memory BIOs: no socket, no thread, no subprocess. GLib and OpenSSL only |
| `tests/test-goodix5120-proto.c` | Unit tests. The vectors come from the Go tests or from bytes observed on the wire |
| `tests/test-goodix5120-tls.c` | Offline rehearsal. An in-process OpenSSL PSK client stands in for the EC |
| `tests/test-goodix5120-driver.c`, `tests/fake-libfprint/` | Actual driver compiled against a test-only libfprint/USB adapter; synthetic lifecycle and failure scenarios |
| `meson.build` | Standalone helper and driver tests, without linking libfprint or USB |
| `libfprint-register.patch` | Registers the driver in a libfprint tree |

## Dropping it into a libfprint tree

```sh
cd libfprint                                  # a libfprint source checkout
mkdir -p libfprint/drivers/goodix5120
cp /path/to/this/dir/goodix5120*.[ch] libfprint/drivers/goodix5120/
patch -p1 < /path/to/this/dir/libfprint-register.patch
meson setup build -Ddrivers=goodix5120 -Dintrospection=false -Ddoc=false
ninja -C build
```

`build/libfprint/fprint-list-supported-devices` should then list `27c6:5120 | Goodix 27c6:5120 behind an ITE EC
(TLS-PSK)`. That tool reads the drivers' id tables and does not open a device.

The driver is registered as **optional**, so only `-Ddrivers=...,goodix5120` builds it. Neither `default` nor
`all` includes it. It uses two existing libfprint helpers, and **libfprint gains no new dependency**:

- `openssl` (≥ 3.0) is already required by `uru4000`. It is used here for the TLS-PSK server.
- `pixman` is already required by the `aes3k` family. It is used here to enlarge the image (see below).

`27c6:5120` is still in libfprint's generated "known unsupported" list. The patch leaves it there while the driver
is optional, and the hwdb tool warns about the overlap.

Tested against libfprint master `6f9479c`. The patch was dry-run against a clean checkout, and the whole library was
built with `-Ddrivers=goodix5120,goodixmoc` with no warnings from this driver under libfprint's warning flags.

## The PSK

The EC and the host share a 32-byte TLS pre-shared key. The driver reads it as a **raw 32-byte file, not hex**, the
form `goodix-dpapi -out` writes:

1. from the path in `GOODIX5120_PSK_FILE`, if set;
2. otherwise from `/var/lib/fprint/goodix5120/psk.bin`.

If the file is missing or is not exactly 32 bytes (a 64-character hex file is refused, not truncated), open fails
with a message naming both locations, and no USB traffic happens. A file readable by group or others draws a
warning. It should be `0600 root:root`. For fprintd, set the variable with `systemctl edit fprintd`
(`[Service]` / `Environment=GOODIX5120_PSK_FILE=...`), or use the default path, which sits inside fprintd's own
state directory.

### PSK provisioning (open Phase 6 decision)

**TODO(provisioning):** the driver does not provision a PSK and cannot. The only known way to write one is `0xe0`
(`preset_psk_write`). That opcode is destructive: it overwrites the key Windows provisioned and breaks Windows Hello
until Windows provisions again. It is absent from this driver on purpose. Until the decision in PLAN.md Phase 6 is
made with upstream:

- **dual-boot machines:** unseal the key from Windows with `goodix-dpapi` (`docs/dpapi-runbook.md`);
- **Linux-only machines:** unsupported. Provisioning would need `0xe0`, and it would first have to be shown that the
  device recovers afterwards.

## What goes on the wire

Open (`img_open`). This is the vendor's `vendorInit` from `cmd/goodix-probe/vendor.go`, in the order Runs 18 and 20
ran it live:

```
drain
a8 00 00                      health check: ACK + "GF_ITE_EC_20063", else stop
drain
96 01 02                      no reply
a8 00 00                      ACK + version
ae 55 a2 52 00 00             data only (20 bytes), no ACK
e4 03 00 02 bb 00 00 00 00    ACK + 41 bytes (PSK hash; never logged)
a2 01 14                      ACK + 01 00 08
82 00 00 00 04 00             ACK + a2 04 25 00 (chip ID 0x2504)
a6 00 00                      ACK + 64 bytes OTP (never logged)
a2 01 14                      ACK + 01 00 08
70 14 00                      ACK only
98 c8 0b be 00 bc 00 bc 00    ACK + 01 01
90 <224-byte config>          ACK + 01 01
d0 00 00                      no ACK: the EC opens a TLS handshake
  <- ClientHello              (EC is the TLS client, host the server)
  -> ServerHello, ServerHelloDone      one 0xb0 pack each
  <- ClientKeyExchange, ChangeCipherSpec, Finished   three transfers, all read
  -> ChangeCipherSpec, Finished        one 0xb0 pack each
d4 00 00                      ACK only
ae 55 a2 52 00 00             data only; TLS bit set or immediate status 00 after authenticated TLS + d4 ACK
drain
```

There is a short drain (200 ms of quiet) after each init step, never after `0xd0`. TLS is 1.2 with suite `0x00ae`
`TLS_PSK_WITH_AES_128_CBC_SHA256` and identity `Client_identity`. There is no identity hint, so no
ServerKeyExchange, and the vendor's flight has none either. Records are forwarded verbatim. An alert the host side
generates is **not** sent to the EC; the Go bridge does the same.

Capture loop. Libfprint's image-device states drive it:

```
AWAIT_FINGER_ON   32 0c 01 (80 t)x6 <u16 ms>   ACK, then wait (no timeout) for the 0x32 event
                  0x32 80 00 00 00 "base invalid" -> re-arm 0x32 from its readings >> 1
                  0x32 02 00 <flags> 00 finger down -> up thresholds from its readings
CAPTURE           20 01 00                      ACK, then one 0xb0 pack: one TLS application-data record
AWAIT_FINGER_OFF  34 0e 01 (80 t)x6             ACK, then wait for 0x34 00 02 00 00 finger up
                                                -> next down thresholds = its readings >> 1
```

Threshold rules (Phase 5d, from `dump.pcapng` and the vendor debug log):

- **down:** no-finger reading `>> 1`. The first arm after load uses this unit's observed baseline
  `b8 c5 ab b9 aa b9`.
- **up:** for zone `i` with bit `i` of the down event's touch flags set, `(reading >> 1) + fdt_delta`; otherwise
  `0x19`. `fdt_delta` = 27 on this unit ("OTP tcode 272, fdt delta 27"); the vendor's default is 21.
- Every threshold is clamped to one byte.

Image: 7693 bytes of plaintext = an 8-byte header, 7680 bytes of samples and a 5-byte trailer (Run 20). A bare
7680-byte frame is also accepted, as `image.TrimFrame` accepts it; any other length is refused rather than guessed.
The samples are 12-bit, packed four to six bytes, **64 columns × 80 rows**, stretched to 8 bits per frame: the samples at
the 1st and 99th percentile become 0 and 255, values between map linearly and outliers clamp
(`g5120_samples_to_gray8_stretched`; a flat frame falls back to the Go reference's `>> 4`). The debug log reports
the two bounds, never pixels. The frame is then enlarged ×3 to 192 × 240 with pixman, as `aes4000` does for its small press sensor.

## Tests (offline, no device)

```sh
meson setup build-c libfprint/goodix5120
meson test -C build-c -v
# the same under sanitizers:
meson setup build-c-asan libfprint/goodix5120 -Db_sanitize=address,undefined && meson test -C build-c-asan
```

Needs GLib/GObject/GIO and OpenSSL development headers. These tests cover:

- **framing:** the golden frames from `internal/proto/packet_test.go`, the checksum wrap cases, round trips with USB
  padding, and four replies **observed from this device** whose checksums must verify (the `0xa8` version reply, two
  ACKs, the unsolicited `0x32` event);
- **gate:** no `0xe0`, `0xf0`, `0xb0` or `nop`; empty `0xe4` refused; the vendor init order and payloads; the
  `0x90` config's `sum & 0xff == 0xaa`; a TLS pack holds exactly one whole record;
- **FDT:** the shared arm vectors in `internal/testfixtures/testdata/protocol.ini`, every event header counted in `dump.pcapng`, zone
  decoding, and the down/up threshold rules including clamping. `run22-session` replays Run 22's three touches:
  from the baseline arm and each logged event it must derive every up arm the probe sent (`ba198e9884ac`,
  `bf19839a969c`, `9ea8a0a491a0`, a zone without its touch flag getting `0x19`) and each next down arm
  (`b9c6acbaabba`, `b8c5abb9aab9`), all of which the EC accepted;
- **image:** the 12-bit vectors from `internal/image/image_test.go`, a 64 × 80 round trip, and the frame-layout rules
  from `frame_test.go`;
- **TLS:** a full handshake against an OpenSSL PSK client configured like the EC (no EMS, no ETM, no tickets). The
  record lengths must be **the vendor's own**: ServerHello 86 bytes, ServerHelloDone 9, ChangeCipherSpec 6, Finished
  85 (the driver log's "SENT DATA LEN"), with the EC side sending four records. A 7693-byte frame must encrypt to the
  7744-byte record body and 7753-byte pack seen in the vendor capture, and decrypt intact when fed in two pieces.
  Also covered: a wrong PSK is reported as a key mismatch with no alert left queued for the EC, an alert from the EC
  is reported, and the PSK file rules.
- **shared reference:** Go and C independently check all 14 init payloads, every config byte, reply expectations,
  FDT vectors and complete synthetic images against [one committed corpus](../../internal/testfixtures/testdata/README.md).
  The actual driver's additional health check and all init writes are checked during a real synthetic TLS session.
- **actual driver:** open, activation, five synthetic enrollment stages in one TLS session, processing before/after
  lift, final-stage deactivation during lift, cancellation in every FDT/capture state and USB yield, unplug at every
  open transfer, read/write failures, short writes, timeouts, wrong ACKs, stale/unexpected messages, base-invalid
  rearming/exhaustion, close/reopen, and strict init reply lengths/status/chip ID/final TLS state. Rejected replies
  must stop further writes; positive cases keep secret and undocumented fields opaque. The adapter preserves
  synchronous state-machine callbacks and asynchronous
  USB completion; no device discovery or USB library is linked. See [the harness guide](tests/README.md) for its
  boundaries. These tests do not establish timing on hardware, matching quality, or real libfprint/GUsb integration.

## What is not done, or stubbed

- **Agents never run hardware.** The Phase 6a/6b offline gate is complete; only the owner may perform the
  first capture under the procedure below. Nothing has checked this driver's timing or its `libusb`/GUsb
  transfer behaviour against this EC. The FDT loop has run live only through the Go probe (Runs 21 and 22).
- `0x98` (set DAC) sends **this unit's** OTP-derived values, and `fdt_delta` is **this unit's**. Both have to be
  derived from the `0xa6` OTP reply before the driver can serve a second machine, and the derivation is not known.
  PLAN.md also lists the OTP-derived DAC values as something never to publish. That makes them a blocker for
  upstreaming as well as a correctness issue.
- **The vendor's post-init calibration is not sent:** step 15 of its init (`36`, `50`, `36`, `82 …`, `20`, `36`).
  Neither is the `0x50` "nav mode" it sends after each finger-up, which appears only in the driver log.
- No suspend/resume handling, and no command that ends a session on close. The EC keeps its TLS session and last FDT
  arm, as Windows leaves it.
- PSK provisioning (see above).
- No umockdev recording under `tests/` in libfprint style, because making one needs the device. Captures also must
  not enter this repository.

## Open questions and risks for the live bring-up

1. **Matching quality.** 64 × 80 is about 3.3 × 4 mm at the usual 50.8 µm pitch. NBIS may find too few minutiae even
   after ×3 enlargement. The community `goodixtls` fork (80 × 88 parts) moved to the SIGFM matcher for this reason.
   `G5120_ENLARGE_FACTOR`, `G5120_BZ3_THRESHOLD` (24) and the default 5 enrol stages are unvalidated guesses.
2. **Ridge polarity and contrast.** Unknown whether ridges are dark. If they are not, set
   `FPI_IMAGE_COLORS_INVERTED`. `>> 4` uses half the range: Run 22's three frames span 52–179 after it, with a
   standard deviation of about 23, and Run 32's `>> 4` frame yielded no minutiae. The per-frame stretch is not a
   calibration: without a background frame, uneven sensor response is stretched along with the ridges.
3. **Timing.** The live Go runs waited seconds between steps. The vendor waits for nothing. This driver waits for
   each reply plus 200 ms of quiet. The handshake itself has no host-side waits, which is the part that mattered
   (Runs 11 and 17).
4. **The drain at open** consumes a stale `0x32` event from an EC Windows left armed. An event that arrives
   between that drain and the first arm is dropped as stale before the arm's ACK.
5. **Base invalid with zeros.** Tonight's reading is that a base-invalid event carries current readings. The older
   note in `internal/proto/fdt.go` says zeroes. If it is zeroes, the driver keeps its previous thresholds, and gives
   up after 8 in a row. Each activation resets that retry budget, including after cancellation or close/reopen;
   rearming within an operation keeps the count. No live run has seen the event yet: Runs 21 and 22 armed down
   four times without one.
6. **ACK status.** Only `0x01` has ever been seen, and anything else stops the driver. That may be too strict.
7. **What the EC is left in after a failure.** A handshake failure (wrong PSK, timeout) probably leaves the EC stuck.
   The driver says so and sends nothing more; the next open's health check then refuses. Sending a TLS fatal alert
   to unstick it is untested ("Recovering the EC", item 4) and deliberately not done.
   After an image, TLS or transport failure during an operation, the driver discards its TLS session and refuses
   activation until close/reopen. Late capture/FDT state changes send nothing. This also applies to unrelated
   errors during deactivation; normal cancellation of a healthy operation remains reusable. Reopening repeats
   the health check and full init, but recovery after a failed operation has only been tested with a synthetic EC.
8. **Autosuspend.** The hwdb gives this device `ID_AUTOSUSPEND=1` (already true today through the unsupported list).
   Whether USB autosuspend between sessions upsets the EC is unknown.
9. **Kernel driver.** `cdc_acm` is not bound on this machine. If it binds elsewhere, the claim detaches it
   (`G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER`). Close and failed-open rollback use the same flag to
   request reattachment, only after a successful claim. Offline tests cover a bound driver and both release/
   attachment failure paths; real kernel-driver restoration remains unverified. A cleanup failure prevents
   reopening that device object: recreate it before retrying, without assuming that fixes kernel binding.
   [GUsb detaches before claiming](https://github.com/hughsie/libgusb/blob/0.4.9/gusb/gusb-device.c#L1602)
   and performs no rollback if the claim itself fails; its public API offers no separate attach operation.
10. **Re-init after a completed session.** Each open repeats the full init and handshake. Runs 18, 20, 21 and 22
    did that four times with no EC reset in between (the `0xae` counter rose by 2 each time), each run a separate
    process that exited without closing TLS. Those opens were minutes to hours apart. Many opens in quick
    succession, as fprintd makes them, have not been tried.

## First live run (owner only, keyboard-safe procedure)

The [first-capture runbook](../../docs/c-driver-first-capture.md) provides the pinned build,
exact owner commands, expected log milestones, private output handling, and result checks.
The current driver has been rebuilt against real libfprint `6f9479c3d55f847c1b3769f28ceb99227f9858cf`
with only `goodix5120` enabled after aligning OUT submissions with the Go reference. The candidate
in `dist/goodix-owner-c-packet-writes/` has compile/offline evidence but reproduced the TLS rejection
in Run 25. It is retained for diagnosis; do not repeat it as a proposed fix. The record-pacing
bundle `dist/goodix-owner-c-pacing/` also failed with an owner-reported EC crash; its final error
is unavailable. The reviewed minimum-interval driver `2b77542` completed TLS in Run 26 but rejected
the immediate status `0x00`; retain that bundle for diagnosis. `d6a9701` (Run 27) reached `0x20` but got
no image, as did the Go-timed settle build (Runs 28/29). The current source, which adds a 5 s
listen after the `0xd4` ACK, drew Run 32's image with paced records; the current source adds the
contrast stretch and has 257 passing
standalone C tests normally and under ASan/UBSan (leak detection disabled). Use the new revision
prepared in the capture runbook. No successful live C capture is established yet.

As with `--bisect`, the owner runs this with an **external keyboard attached** and a passing firmware
health check. Recovery is required for a failed health check or an unfinished/crashed TLS session;
Run 26's local gate failure alone is not evidence that recovery is needed:

1. Check the EC answers with `goodix-probe --bisect --read-state` first, per `docs/bisect-runbook.md`.
2. Build libfprint with only this driver. Run a single capture with libfprint's `examples/img-capture` (not fprintd),
   with `G_MESSAGES_DEBUG=all` and `GOODIX5120_PSK_FILE` pointing at the key in `captures/`.
   Ensure `FP_DEBUG_TRANSFER` is unset (`env -u FP_DEBUG_TRANSFER ...`); do not enable raw transfer dumps.
3. Compare the debug log against Runs 20–22 step by step (arm thresholds, event headers, the 7753-byte image
   pack, the lift). Stop at the first difference.
4. Record the capture, lift, close, and keyboard outcome before proceeding to Phase 6c's lifecycle and
   enrollment / matching tests. fprintd integration and PAM remain separate validation steps.
