# First C-driver enrollment and verification (owner only)

Phase 6c's first hardware check after Run 34's first complete C capture
([first-capture procedure](c-driver-first-capture.md)). Agents must not run it. It uses libfprint's own
pinned `examples/enroll` and `examples/verify`; this is not fprintd or PAM, and nothing is installed.

**Run 35** (`docs/protocol.md`) completed enrollment: 5/5 stages in one session, one NBIS retry,
finger number `7` (labelled right middle; physically the right index finger, as the owner noted after Run 38). Its template is in the owner's private run directory. Verification is pending.

**From Run 42 on, use [Repeat runs](#repeat-runs-after-run-41) at the end.** It drops the health check and
the keyboard report, and the log is short enough to paste whole. The sections in between record how Runs 35–41
were done.

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

Decide on both fingers before starting, for example right index for A and **left thumb** for B (Run 38
accidentally used the right index for both). Switch fingers when `=== finger B` appears.
Report the `keypoints:` lines and everything from `=== SIGFM scores` onward.

**Not yet in the driver: background subtraction.** The fork's `goodix511` driver subtracts a no-finger
calibration frame from every frame before its min–max scaling. It takes that frame before each scan with
FDT-up, nav `0x50` and `0x20`, a sequence never sent to this EC. This driver has no such subtraction. It is
a candidate for improving both matchers, but it needs its own live step first.

**Run 38** (`docs/protocol.md`) ran this tool, but all twelve touches used the same finger (right index), so it
measured repeatability only. Every frame had 82–147 keypoints. All six A touches matched each other, but 3 of the
6 later touches matched no A frame at threshold 24. Impostor scores still need a run with a different finger for B.

**Run 39** used two fingers. All impostor pairs scored 0, but only 3 of 6 genuine attempts matched the other five
A views. The next run is the same command with `15` instead of `6` (30 touches): it shows whether a larger template
fixes the genuine rejections.

**Run 40** (`15`): 14/15 genuine attempts matched the other 14 views. One B touch was accidentally the index finger and
matched; the other 14 B touches scored at most 9.

## SIGFM driver: enroll and verify (after Run 40)

`dist/goodix-owner-c-sigfm-driver/` (ignored by Git, local only) is a **new driver build**, commit `9c682a6`.
The driver matches with SIGFM itself instead of NBIS (`libfprint/goodix5120/README.md`, "Matching"). It is
compiled into the pinned libfprint `6f9479c3` in `goodix-offline-build-opencv:26.04`, `--network none`. The bundle
contains libfprint's own `enroll`, `verify`, `identify` and `img-capture` from that build. They link the host's
OpenCV 4.10, and `ldd` on the host resolves every library. `provenance.txt` and `SHA256SUMS` record the build.
No executable was invoked during preparation.

What changed for the owner, and what did not:

- **The wire sequence is unchanged:** the open, health check, TLS and touch frames are those of Runs 34–40.
  One difference: every touch now waits for the finger-up event, including the last enrollment stage. The old
  image-device class cancelled that last wait (Run 35). Close still sends nothing.
- **Enrollment needs 15 touches** in one session (Run 40 did 30 captures in one session). Lift the finger after
  each touch, and shift the placement a little between touches, so the views cover more of the finger.
  A touch with too few SIFT features is a retry (`Enroll stage N of 15 failed with error … press the finger
  flat`); touch again.
- **No update question.** This driver does not offer `FP_DEVICE_FEATURE_UPDATE_PRINT`, so `enroll` does not ask
  "Should an existing fingerprint be updated". It prints a line saying old prints will be erased.
- **Use a fresh directory.** The template from Run 35 is an NBIS print, which this driver refuses with
  `DATA_INVALID` before sending anything. The new `test-storage.variant` holds SIGFM features, about 200 KB per
  finger. That is biometric data. No `enrolled.pgm` or `verify.pgm` is written any more: the prints carry no image.

Health check first, from the repository root, with the external keyboard attached:

```sh
go build -buildvcs=false ./cmd/goodix-probe
sudo ./goodix-probe --bisect --read-state
```

Enroll the right index (finger number `6`):

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
build="$repo/dist/goodix-owner-c-sigfm-driver"
umask 077
run=$(mktemp -d "$HOME/goodix-c-sigfm-XXXXXX")
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  sh -c 'umask 077; cd "$1" || exit 1; shift; exec "$@"' sh "$run" \
  stdbuf -oL "$build/examples/enroll" 2>&1 | tee "$run/enroll.log"
```

Then verify in the same terminal (same `$run`). Choose finger `6`, and at each `Verify again? [Y/n]` answer `y`:

```sh
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  sh -c 'umask 077; cd "$1" || exit 1; shift; exec "$@"' sh "$run" \
  "$build/examples/verify" 2>&1 | tee "$run/verify.log"
```

Decide both fingers before starting. Make **five attempts with the right index**, placed differently each time,
then **five with the left thumb**, then answer `n`. Expect `MATCH!` for the index and `NO MATCH!` for the thumb.
A `retry error reported` line is a quality retry, not a fault. Ctrl-C on the external keyboard stops at any
warning or error other than the known PSK-permission warning, or if the keyboard misbehaves.

Report these lines from both logs. They contain no pixels, keys or templates:

- every `Enroll stage N of 15` line, and the final result;
- `SIGFM: N keypoints`, `enroll view N: best SIGFM score …` and `print 0: best SIGFM score N, threshold 24`;
- every `MATCH!` / `NO MATCH!` / `retry error reported` line, in order, saying which finger each attempt used;
- every `image: stretched 12-bit samples LO..HI` line;
- any warning or error, and keyboard behaviour during and after each run.

Never post `test-storage.variant`. Results go in `docs/protocol.md` as Run 41 and in PLAN.md Phase 6c.
Ten attempts in one session say nothing about another day; repeat verify later from the same `$run` before
calling the threshold settled.

## Repeat runs (after Run 41)

Forty-one runs and Run 41's clean enroll/verify have made the touch path routine. The owner keeps the USB
keyboard to hand (not plugged in) and reboots if the internal keyboard ever stops; if a reboot does not bring it
back, use the [EC recovery](protocol.md#recovering-the-ec-researched-offline-2026-09-30) (charger plugged in, power button 40 s). There is no
separate health check any more: a stuck EC makes the driver's own open fail, before any TLS, with the reason in
the log.

The driver logs milestones only: firmware, TLS up, `finger down` / `finger up`, image contrast, keypoints and
scores. Every ACK, reply, send, TLS record and finger-detect reading is behind `GOODIX5120_TRACE=1`, and
`G_MESSAGES_DEBUG` names only the driver's domain, so libfprint-core and GUsb debug stay out. Nothing printed
contains pixels, keys, the `0xe4`/`0xa6` replies or templates, so the whole log can be pasted.

The PSK path is the root-only copy made by the [fprintd installer](fprintd.md) (run its `install` once first).
`captures/` is on a `fuseblk` mount that ignores `chmod`, so the original always logs the permission warning
(Run 42).

Once per terminal:

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
build="$repo/dist/goodix-owner-c-sigfm-driver"
g5120() {
  sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=libfprint-goodix5120 \
    ${GOODIX5120_TRACE:+GOODIX5120_TRACE=$GOODIX5120_TRACE} \
    FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE=/etc/goodix5120/psk.bin \
    sh -c 'umask 077; cd "$1" || exit 1; shift; exec "$@"' sh "$run" \
    stdbuf -oL "$build/examples/$1" 2>&1 | tee -a "$run/$1.log"
}
```

Verify against the existing template (newest `~/goodix-c-sigfm-*`), or enroll a new one in a fresh directory:

```sh
run=$(ls -dt "$HOME"/goodix-c-sigfm-* | head -1); g5120 verify     # or: g5120 identify
umask 077; run=$(mktemp -d "$HOME/goodix-c-sigfm-XXXXXX"); g5120 enroll
```

Say which finger each attempt used, and paste the terminal output. Only if something fails and the milestones do
not explain it, repeat that one run as `GOODIX5120_TRACE=1 g5120 verify` for the wire-level log.
`test-storage.variant` stays private, as before.
