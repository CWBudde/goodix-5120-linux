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

## Limits and next regression targets

This adapter does not run libfprint's action framework, GUsb, libusb, Pixman or NBIS. Fake resizing preserves ownership
and dimensions using nearest-neighbour sampling; production uses Pixman bilinear interpolation. It cannot validate
enrollment quality, matching, timing, suspend or EC recovery.

The remaining Phase 6b tasks still require response-content validation, failed-session invalidation, completion on
the final permitted image read, per-operation retry reset, symmetric interface release and shared independent
protocol fixtures. Recovery tests here use an explicit close/reopen with a healthy synthetic EC; they do not assert
that immediate activation after a failed session is safe. Keep the first hardware-run gate in `PLAN.md`.
