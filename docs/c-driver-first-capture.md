# First C-driver capture (owner only)

Phase 6b's offline gate is complete. This run checks one open → touch → image → lift → close
against the real libfprint integration. Agents must not run it. Use this prototype only on the
original tested machine/profile; firmware identity alone does not establish calibration compatibility.
Enrollment, matching, repeated lifecycle tests, and PAM remain Phase 6c work.
Run 23 stopped at a mis-transcribed `0xe4` reply header. Run 24 passed the corrected full init,
then received fatal TLS `decode_error (50)` after the first server flight; both keyboards worked
after exit. Run 25 tested the completed 64-byte OUT submissions below and received the same
fatal alert; both keyboards still worked. A successful C capture remains pending.
The owner also reports an EC crash using `dist/goodix-owner-c-pacing/`; its final error is not
available. Do not repeat either bundle. The reviewed source tests a 60 ms minimum interval between
host records while reading IN, preserving that deadline across unrelated input and completing partial
TLS records before more output. This is an unproven timing hypothesis, not a confirmed vendor requirement.
Run 26 used reviewed driver `2b77542`: authenticated TLS completed, `0xd4` ACKed, and an immediate
20-byte MCU reply with status `0x00` failed the local TLS-bit gate. Both keyboards worked; no image
was requested. The corrected gate permits exactly that immediate status after authentication and
positive ACK; other bit-clear states remain errors. The earlier bundles are superseded.
The timing cause/minimum remains unproven; targeted diagnostics are follow-up evidence.
Run 27 used `d6a9701`: open succeeded and the touch was reported, but `0x20` drew no image and the
EC's TLS bit stayed clear. The current source sends the final TLS flight back to back and `0xd4`
after a 10 ms settle read, matching the Go timing of Run 18 (`docs/protocol.md`, Run 27).
Runs 28/29 used that settle build and reproduced Run 27. The current source also reads IN for 5 s
after the `0xd4` ACK before sending `0xae`, as Go's probe did after `0xd4` in Run 18; open therefore
pauses about 5 s after the TLS-complete log line. Run 30 ran it: no image, TLS bit still clear.
Run 31, a Go capture from the same bit-clear state, got an image. Every failing C run had one pair of
host writes within ~1 ms; the current source paces ChangeCipherSpec/Finished by 60 ms again while keeping
the settle and listen windows, so no two host writes are closer than 10 ms (`docs/protocol.md`, Run 31).
Run 32 ran that bundle from Run 31's bit-set state: `0x20` drew and decrypted an image, then libfprint
found no minutiae and saved no file (`docs/protocol.md`, Run 32). The current source replaces the
`>> 4` grey mapping with a per-frame contrast stretch and logs its bounds. Run 33 reran the unpaced
listen bundle from the same bit-set state: no image, bit cleared — the pacing, not the start state,
made Run 32 work. Do not reuse the listen bundle.

## Prepare the build offline

The superseded local bundle is `dist/goodix-owner-c-pacing/` in this repository (ignored by
Git, retained across reboot), built from the original staged record-pacing driver on top of `dbdb6d0`
(`provenance.txt` records the staged diff's hash). It was built in an `ubuntu:26.04` container to
match the host. It contains only `goodix5120`, uses the bundled libfprint through its executable
RUNPATH, and was not installed system-wide. Build logs, `provenance.txt`, and binary `SHA256SUMS`
are included. It predates the review refinements and must not be used to test the current source.
The bundle is local, not distributed with the repository. Prepare a new revision-labelled bundle
after review and record its source revision and checksums.

**Prepared 2026-10-01:** `dist/goodix-owner-c-2b77542/` contains exact driver commit
`2b77542ea3c8cc8c951123d6637f7a877deb5694` and the pinned libfprint below, compiled in Ubuntu 26.04.
All 245 C subtests pass normally and under ASan/UBSan (leak detection disabled). Host linkage resolves
the bundle's library without missing dependencies, and the driver table lists only `27c6:5120`.
`provenance.txt`, source hashes, build/test logs and `SHA256SUMS` record preparation; hardware outcome
is recorded as Run 26. This bundle predates the immediate MCU-state fix; do not reuse it for capture.
The capture executable was not invoked by agents, and no hardware was accessed during preparation.

**Superseded by Run 27:** `dist/goodix-owner-c-d6a9701/`, from exact driver commit
`d6a9701af7355e31d67cce3066f490fec0278fa2`, with the same pinned upstream. All 251 C tests pass normally
and under ASan/UBSan (leak detection disabled); `just check` passes with existing formatting listings.
The pinned build has no compiler warnings. Source/fixture hashes match the commit, host linkage resolves
the bundled library without missing dependencies, and the driver table lists only `27c6:5120`.
Provenance, build/test logs and `SHA256SUMS` are included. No agent accessed hardware.

**Superseded by Runs 28/29:** `dist/goodix-owner-c-settle/`, built offline from the working
tree on `8cb3957` (driver diff hash in its `provenance.txt`). 252 C subtests pass normally and under
ASan/UBSan; no compiler warnings; host linkage and the driver table check out. No agent accessed hardware.

**Superseded by Run 30:** `dist/goodix-owner-c-listen/`, the settle change plus the 5 s listen after
the `0xd4` ACK, built from the working tree on `8cb3957`.

**Superseded by Run 32:** `dist/goodix-owner-c-gaps/`, the listen bundle plus the 60 ms pace between
ChangeCipherSpec and Finished; exactly commit `70317c9`. It drew an image that failed minutiae detection.

**Contrast-stretch bundle, 2026-10-02:** use `dist/goodix-owner-c-stretch/`, built offline from the working
tree on `70317c9` (driver diff hash in its `provenance.txt`). It adds the per-frame 1st/99th-percentile
contrast stretch to the gaps bundle. 257 C subtests pass normally and under ASan/UBSan; no compiler
warnings; host linkage and the driver table check out. No agent accessed hardware. Besides the checks
below, report the `image: stretched 12-bit samples LO..HI` line.

To reproduce in a **new** libfprint checkout, with a C/C++ toolchain, Meson, Ninja, pkg-config,
and GLib, GUsb, libusb, OpenSSL ≥ 3, and pixman development packages:

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git /tmp/goodix-owner-libfprint
cd /tmp/goodix-owner-libfprint
git checkout --detach 6f9479c3d55f847c1b3769f28ceb99227f9858cf
driver_source=$(mktemp -d /tmp/goodix-owner-driver-XXXXXX)
git -C "$repo" archive d6a9701af7355e31d67cce3066f490fec0278fa2 libfprint/goodix5120 \
  | tar -x -C "$driver_source"
mkdir -p libfprint/drivers/goodix5120
cp "$driver_source"/libfprint/goodix5120/goodix5120*.[ch] libfprint/drivers/goodix5120/
patch --batch -p1 < "$driver_source/libfprint/goodix5120/libfprint-register.patch"
meson setup build -Ddrivers=goodix5120 -Dintrospection=false -Ddoc=false \
  -Dudev_rules=disabled -Dudev_hwdb=disabled -Dinstalled-tests=false -Dgtk-examples=false
meson compile -C build
build="$PWD/build"
```

For the prepared bundle, set `build="$repo/dist/goodix-owner-c-stretch"` instead.
Do not install the library or change fprintd/PAM configuration for this run. The following tool
reads compiled driver ID tables without opening USB:

```sh
"$build/libfprint/fprint-list-supported-devices"
ldd "$build/examples/img-capture"
```

Expect just `27c6:5120` in the USB table, no missing libraries, and `libfprint-2.so.2` resolved
inside this build. Do not invoke `img-capture` as an offline smoke test: it opens hardware.

## Check the EC

Attach and test an **external keyboard**, save other work, and follow the
[bisect runbook](bisect-runbook.md#before). If TLS was unfinished/crashed or the health check fails, recover first:
shutdown, charger **plugged in**, power button held **40 seconds**, then boot. There is no
automatic reset or retry. Run 26's completed handshake and local gate rejection alone do not require
a reboot; confirm responsiveness with the health check. Ensure no other client is using the device.

From the repository root:

```sh
go build -buildvcs=false ./cmd/goodix-probe
sudo ./goodix-probe --bisect --read-state
```

The run needs no input. Continue only if the health check passes. A failed health check or a
new MCU state means stop and follow the runbook's recovery procedure; do not start the C capture.

## Run exactly one capture

In the same terminal, set `build` to the prepared path below, or substitute your reproduced build's
absolute path:

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
build="$repo/dist/goodix-owner-c-stretch"
umask 077
run=$(mktemp -d "$HOME/goodix-c-first-XXXXXX")
sudo env -u FP_DEBUG_TRANSFER G_MESSAGES_DEBUG=all \
  FP_DRIVERS_ALLOWLIST=goodix5120 GOODIX5120_PSK_FILE="$repo/captures/goodix-psk.bin" \
  sh -c 'umask 077; exec "$@"' sh \
  "$build/examples/img-capture" "$run/frame.pgm" 2>&1 | tee "$run/capture.log"
```

Use your existing **raw 32-byte** PSK file; adjust its path if needed. Never print its contents.
Use a filesystem that enforces Unix permissions for the capture directory: this machine's home
directory is ext4, while the repository's `fuseblk` mount reports `775` despite `chmod` and `umask`.
On ext4 the fresh directory and log are private; the root shell explicitly sets `umask 077` so
the example writes a root-owned `0600` image. A known PSK-permission warning may appear when using
the existing key on `fuseblk`; the driver accepts it, but other local users may be able to read it.
Leave `FP_DEBUG_TRANSFER` unset: raw transfer tracing can reveal secrets and images.

Watch the log. When `arming 0x32` appears, place one finger. When `arming 0x34` appears, lift it.
Stop at the first unexpected exchange or warning/error other than that known PSK-permission
warning, or keyboard failure (Ctrl-C on the external keyboard). Check typing during the wait and after exit.
Preserve the log. An unfinished handshake, keyboard failure or failed health check requires recovery
as described above; a local validation error after completed TLS does not by itself establish a wedge.

## Judge and record the result

Compare the log with Runs 20–22 in [the protocol evidence](protocol.md):

- Firmware is `GF_ITE_EC_20063`; init completes without rejected replies.
- Authenticated TLS completes and `0xd4` ACK status is `0x01`. The final MCU reply is exactly 20 bytes,
  with the TLS bit set or immediate status `0x00`. The informational clear-bit log is expected for Run 26's
  status and is not a warning/error; it does not mean the decoder considers the bit set.
- Initial down thresholds are `b8 c5 ab b9 aa b9`; a down event leads to one image request.
- The observed image pack was 7753 bytes, containing a TLS record with a 7744-byte body; the driver's image
  log should report `7693 plaintext bytes, 8-byte header + samples + 5-byte trailer`.
- An up arm/event follows, the image is saved, and close completes without an error.
  Event readings and derived up thresholds vary with finger placement; compare their rule, not
  exact Run 22 values. Unexpected base-invalid events are new hardware evidence to record.

The pinned upstream `img-capture` always returns `EXIT_FAILURE`, including after saving an image.
Depending on `pipefail`, the pipeline reports `tee`'s result or the example's failure. Neither proves
capture success. Inspect the log for save/close errors and check the image header without displaying
biometric pixels:

```sh
sudo head -n 1 -- "$run/frame.pgm"
sudo stat -c '%a %s bytes' -- "$run/frame.pgm"
```

Expect `P5 192 240 255` and 46095 bytes: the driver's 64 × 80 image is enlarged threefold.
After successful close, transfer ownership to view the private image locally:

```sh
sudo chown -- "$(id -u):$(id -g)" "$run/frame.pgm"
```

Report the last successful milestone, any error, keyboard behavior, and header/size. Keep the
PSK and image local; review logs before sharing. A saved frame alone does not validate enrollment
or authentication. Record the outcome in `docs/protocol.md` and `PLAN.md` before proceeding.
