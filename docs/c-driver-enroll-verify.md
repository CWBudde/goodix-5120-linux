# First C-driver enrollment and verification (owner only)

Phase 6c's first hardware check after Run 34's first complete C capture
([first-capture procedure](c-driver-first-capture.md)). Agents must not run it. It uses libfprint's own
pinned `examples/enroll` and `examples/verify`; this is not fprintd or PAM, and nothing is installed.

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
