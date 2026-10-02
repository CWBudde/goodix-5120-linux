# First C-driver enrollment and verification (owner only)

Phase 6c's first hardware check after Run 34's first complete C capture
([first-capture procedure](c-driver-first-capture.md)). Agents must not run it. It uses libfprint's own
pinned `examples/enroll` and `examples/verify`; this is not fprintd or PAM, and nothing is installed.

**Run 35** (`docs/protocol.md`) completed enrollment: 5/5 stages in one session, one NBIS retry,
right middle finger (`7`). Its template is in the owner's private run directory. Verification is pending.

## The bundle

`dist/goodix-owner-c-enroll/` (ignored by Git, local only) is the **same compiled build** as
`dist/goodix-owner-c-stretch/` — driver commit `17af857`, libfprint `6f9479c3`, Ubuntu 26.04 container,
`--network none`. It adds the `enroll` and `verify` examples from that build without recompiling
(`bundle-enroll.sh`). `img-capture` and `libfprint-2.so.2.0.0` are byte-identical to the stretch bundle.
The device table lists only `27c6:5120`, and `ldd` resolves the bundled library with nothing missing.
`provenance.txt` and `SHA256SUMS` record this. No executable was invoked during preparation.

What the examples do, read from the pinned build:

- `enroll` asks for a finger number on stdin, counted from 0 (`6` = right index, `7` = right middle),
  and needs **5** successful scans.
  The driver does not override libfprint's image-device default stage count, so all five touch/lift
  rounds happen in **one** open/TLS session. That has not been tried in C before. Go did three in one
  session (Run 22).
- `enroll` writes the template `test-storage.variant` and the last stage's image `enrolled.pgm`
  **into the current directory**; `verify` reads `test-storage.variant` from there and writes `verify.pgm`.
  All three are biometric data. The commands below run in a fresh private directory under `$HOME`.
  Never put them in the repository and never share them.
- After open, `enroll` asks `Should an existing fingerprint be updated …? Enter Y/y or N/n`, because
  libfprint's image-device class declares `FP_DEVICE_FEATURE_UPDATE_PRINT`. It prints that prompt and its
  stage messages with plain `printf`, which is block-buffered when stdout is a pipe. Without `stdbuf -oL`
  the prompt stays hidden in the buffer and the program waits silently after `Image device open completed`.
  That happened in Run 35. Answer `n`. Ctrl-C cannot interrupt the wait: GLib's SIGINT handler only runs
  from the main loop, which is blocked in `getchar`.
- `verify` uses `g_print`, which flushes. After each attempt it asks `Verify again? [Y/n]`.

## Before

As for the first capture: attach and test an **external keyboard**, save other work, then from the
repository root:

```sh
go build -buildvcs=false ./cmd/goodix-probe
sudo ./goodix-probe --bisect --read-state
```

Continue only if the health check passes. If it fails, or a TLS session was left unfinished, recover first:
shut down with the charger **plugged in** and hold the power button **40 s**.

## Enroll

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
build="$repo/dist/goodix-owner-c-enroll"
umask 077
run=$(mktemp -d "$HOME/goodix-c-enroll-XXXXXX")
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  sh -c 'umask 077; cd "$1" || exit 1; shift; exec "$@"' sh "$run" \
  stdbuf -oL "$build/examples/enroll" 2>&1 | tee "$run/enroll.log"
```

Enter the finger number (`6` = right index); use the same one for verification. Answer `n` to the
update question. For each stage, place the finger when `arming 0x32` appears and lift it when `arming 0x34` appears. Shift the
placement slightly between stages. A `Reporting retry` or `retry` stage is a quality signal, not an EC fault:
the program asks again. Stop with Ctrl-C on the external keyboard on any warning or error other than
the known PSK-permission warning, or if the keyboard fails. Check typing after the program exits.

## Verify

Only after a successful enrollment, and in the **same terminal** (same `$run`). First run it with the
enrolled finger:

```sh
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  sh -c 'umask 077; cd "$1" || exit 1; shift; exec "$@"' sh "$run" \
  "$build/examples/verify" 2>&1 | tee "$run/verify.log"
```

Choose the same finger number and touch with the enrolled finger: expect `MATCH!`. At
`Verify again? [Y/n]` answer `y` and touch with a **different** finger: expect `NO MATCH!`. Then answer `n`.
Both attempts run in one session and one log.

## Report

From each log, report the lines below, which contain no pixels, keys or templates:

- `Enroll stage N of 5 passed` / failed / retry lines, and the final enroll result;
- every `image: stretched 12-bit samples LO..HI` line;
- `Minutiae scan completed in …` lines, and any `No minutiae found`;
- `score N/24` lines and the `Match report` line from each verify run;
- the health check's MCU state before the run, and whether `immediate MCU status 0x00` appears
  after the listen window (it is absent when the TLS bit is set);
- keyboard behaviour during and after each run, and any warning or error.

Never post `test-storage.variant` or the `.pgm` files. Review logs before sharing.
Results are recorded in `docs/protocol.md` (next run number) and `PLAN.md` Phase 6c.
One genuine match and one impostor rejection do not validate the match threshold. Repeated attempts come after this.

## Minutiae count (after Run 36)

Run 36 scored `0/24` on every compared attempt. That is Bozorth3's value when either print has fewer
than 10 minutiae. `dist/goodix-owner-c-minutiae/` adds `examples/g5120-minutiae`
(`libfprint/goodix5120/tools/g5120-minutiae.c`), built against the same unchanged driver and library.
It opens the device once, captures N frames, and prints for each frame:

- `driver`: libfprint's own minutiae count on the driver's ×3 image (what enroll and verify use).
- `x1`…`x5`: the same frame reduced to 64 × 80 and re-enlarged ×k bilinearly, re-detected.
- `inv`: the ×3 image with inverted colours, which tests ridge polarity.

It prints counts only, and writes no image, template or file. `--selftest` exercises the analysis on a
synthetic pattern without opening anything.

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
build="$repo/dist/goodix-owner-c-minutiae"
sudo ./goodix-probe --bisect --read-state          # health check first, from the repo root
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  "$build/examples/g5120-minutiae" 10 2>&1 | tee "$HOME/goodix-minutiae.log"
```

Touch at each `arming 0x32` and lift at `arming 0x34`. Use one finger and press firmly so that all six
zones are covered. Ctrl-C (external keyboard) cancels. Report the `frame N:` lines and the `summary` line.
A frame whose driver count is 0 is discarded by libfprint, so it has no rescale columns.

## SIGFM scores (after Run 37)

Run 37 measured at most 5 NBIS minutiae per frame, so Bozorth3 cannot match on this sensor.
`dist/goodix-owner-c-sigfm/` adds `examples/g5120-sigfm` (`libfprint/goodix5120/tools/g5120-sigfm.cpp`). It
uses SIGFM, the SIFT-based matcher that the community `goodixtls` fork uses for its 64 × 80 `goodix511`.
SIGFM is compiled from the fork's pinned source (commit `07306bb`, LGPL-2.1+, copied into the bundle,
not into this repository). It links the host's OpenCV 4.10. The driver and libfprint are unchanged.

The tool opens once and captures K frames (default 6) of finger A, then K frames of a different finger B.
For the driver's ×3 image and for a 64 × 80 reduction of it, it prints:

- keypoints per frame (the fork rejects frames with fewer than 25);
- genuine pair scores (A against A) and impostor pair scores (B against A);
- a verify simulation: each A frame against the other A frames, and each B frame against all A frames
  (best score). The fork accepts at a score of at least 24.

It prints numbers only, and writes no image, feature or template. A touch that libfprint discards for
having no NBIS minutiae is repeated.

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
build="$repo/dist/goodix-owner-c-sigfm"
sudo ./goodix-probe --bisect --read-state          # health check first, from the repo root
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  "$build/examples/g5120-sigfm" 6 2>&1 | tee "$HOME/goodix-sigfm.log"
```

Report the `keypoints:` lines and everything from `=== SIGFM scores` onward.

**Not yet in the driver: background subtraction.** The fork's `goodix511` driver subtracts a no-finger
calibration frame from every frame before its min–max scaling. It takes that frame before each scan with
FDT-up, nav `0x50` and `0x20`, a sequence never sent to this EC. This driver has no such subtraction. It is
a candidate for improving both matchers, but it needs its own live step first.
