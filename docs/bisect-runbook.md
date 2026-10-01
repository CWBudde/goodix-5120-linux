# Bisect runbook: which step stops the keyboard?

Run 1 (2026-08-17) killed the internal keyboard, but the kernel logged nothing when it happened
(FINDINGS.md, "What the journal shows"). So nobody knows whether attaching to the device, `nop`,
`firmware_version` (`0xa8`) or `preset_psk_read` (`0xe4`) did it. `goodix-probe --bisect` finds out:
it performs one step at a time. It used to ask for a key press on the internal keyboard after each step;
the `0xa8` health check gates the start, and the probe logs the host's i8042/EC counters after each step.
This initial check does not establish continued EC responsiveness or keyboard health.

**Answered by Run 2 (2026-09-19): `0xe4`** — and narrowed by Run 4 the same evening: what wedges the EC
is an `0xe4` **with an empty payload**, sent on its own, with no `nop` and no `0xa8` before it. See
`docs/protocol.md`. The vendor driver sends `0xe4` with an 8-byte argument in all eight of its inits and
is answered normally.

Two things follow, and both are now enforced in code. Every command carries the payload the vendor sends
(`cmd/goodix-probe/vendor.go`), and the transport refuses a payload that violates an opcode's registered
rule, so **the frame that killed the keyboard can no longer be built**. `nop` is gone from the steps: the
vendor never sends it to an ITE EC and it drew no reply in Runs 2 and 3. A bisect run now covers attach
and `0xa8`.

This is a **live hardware run**. It is the user's decision (made 2026-09-19) to run it before a
vendor-driver capture exists, which departs from the Phase 4 gate in PLAN.md. Claude does not run it.

## What the probe does

| Step | Action | Sends |
|---|---|---|
| baseline | log the host's counters | nothing (the device is not opened) |
| 0 attach | open + claim the USB interface, drain | nothing |
| 1 | `firmware_version` (`0xa8`) with payload `00 00`, collect, drain | 1 frame |
| ~~2~~ | ~~`nop` (`0x00`)~~ — dropped; the vendor never sends it to an ITE EC | — |
| ~~3~~ | ~~`preset_psk_read` (`0xe4`)~~ — removed after Run 2 wedged the EC on it | — |

After each step it logs the i8042 interrupt counts, an **EC refresh counter** and whether `27c6:5120` is still
enumerated. It does not wait for keyboard input. Exit status is 0 if the sequence completes and 1
on failure. The ordinary step collector logs missing replies but currently treats timeout/read-limit
exhaustion as completion; later steps may therefore run after an expected reply is lost. Review the
exchanges, and check typing yourself during and after a live run. A final result is not a health verdict.

The log goes to stdout and to `goodix-bisect-<time>.log`. The file is flushed to disk after every line.
Step markers (`goodix-probe: ...`) also go to the kernel log, so they line up with kernel messages in
`journalctl -k`.

`--steps` accepts an opcode only when its payload is on record from the vendor driver — that is, when it
appears in `vendorInit` or `vendorLoop` in `cmd/goodix-probe/vendor.go`. A `ClassSafe` one passes on its
own: today `a8`, `ae`, `82` and `a6`. That is how one command is added per live run without widening what
the plain probe sends, and a run that asks for something else fails before the device is opened rather
than halfway through.

Every state-changing frame needs **its own flag**, and the flag's help text says what the frame does:

| Flag | Opcode | What it sends |
|---|---|---|
| `--allow-96` | `0x96` enable_chip | `01 02`; the vendor's first frame, no reply expected |
| `--allow-e4` | `0xe4` preset_psk_read | the vendor's 8-byte argument — **never the empty frame**; the reply holds a hash of the device PSK |
| `--allow-a2` | `0xa2` reset | `01 14`; populates the chip-ID register |
| `--allow-70` | `0x70` idle | `14 00` |
| `--allow-98` | `0x98` set_dac | `c8 0b be 00 bc 00 bc 00` — DAC values derived from **this** machine's OTP |
| `--allow-90` | `0x90` upload_config_mcu | the vendor's 224-byte register script; the largest state change in the init |
| `--allow-d0` | `0xd0` request_tls_connection | `00 00`; no ACK — the EC opens a TLS handshake |
| `--allow-d4` | `0xd4` tls_successfully_established | `00 00` |
| `--allow-20` | `0x20` mcu_get_image | `01 00`; the frame comes back as an encrypted TLS record |

A flag lifts the ceiling for that one opcode and nothing else, and only when the run actually sends it —
as a `--steps` entry, or as one of the commands `--tls` sends itself. The ceiling stays `ClassSafe`, and
no flag can admit a destructive opcode: `0xf0` and `0xe0` are not in this build at all.
`TestEveryAboveCeilingVendorFrameIsCatalogued` pins the table above against the vendor catalogue in both
directions, so a new frame cannot become sendable without someone writing down why.

Rehearse any selection offline first. The replay now answers the Phase 5 frames with the ACK the driver
log records for them, so a rehearsal shows the same shape of exchange as the live run:

```sh
./goodix-probe --bisect --replay --allow-a2 --allow-70 --allow-98 --allow-90 \
  --steps a8,ae,a2,82,a6,a2,70,98,90
```

The data replies are **not** invented: `0x98` and `0x90` answer `01 01` in the log, and the rehearsal
sends only the ACK. `0xae` gets no ACK at all there, which is correct — it never does.

## Before

0. **If the previous run used `--tls` and the handshake did not complete, reset the EC first** (step 4 of
   "If the keyboard stops": charger plugged in, 40 s hold). An
   unfinished handshake leaves the EC unable to answer plaintext commands, and it does not recover by itself
   — not on a reset (`0xa2`), not on re-attach. Run 12 (2026-09-20) skipped this, sent the init into an EC
   that was acknowledging nothing, and lost the keyboard at step 8. The probe now sends `0xa8` as a health
   check after attach and refuses to send any step if nothing answers, so a forgotten power cycle costs a
   message rather than a wedge — but the EC reset is still the thing that fixes it.
1. Plug in an **external USB keyboard** and check that it types. After a wedge, you need it to shut down.
2. Save and close everything else.
3. Build: `go build -buildvcs=false ./cmd/goodix-probe`
4. **Rehearse without USB:** `./goodix-probe --bisect --replay` replays Run 1 instead of opening the
   device. Delete the rehearsal log afterwards.
5. Optional, recommended: record raw USB traffic in a second terminal (bus 1). Keep this file out of the
   repo:

   ```sh
   sudo modprobe usbmon
   sudo cat /sys/kernel/debug/usb/usbmon/1u > usbmon-$(date +%Y%m%d-%H%M%S).txt
   ```

## Run

```sh
sudo ./goodix-probe --bisect
```

The run needs no input. It stops on its own if the EC does not answer the health check, and otherwise
ends with `RESULT: every step completed`.

## If the keyboard or the EC stops

1. Stop the usbmon `cat` with Ctrl-C on the external keyboard.
2. Don't try to repair it: no `usbreset`, no atkbd unbind/bind, no suspend. In Run 1 these only added
   noise, and `usbreset` is what made the device disappear from the bus.
3. Optionally, before shutting down, capture:
   `journalctl -k -b --since "-10 min" > kernel-after-wedge.txt` and `ls /sys/bus/usb/devices/`.
4. **EC reset:** `systemctl poweroff`, **leave the charger plugged in**, hold the power button **40 s**, then
   boot. Check with `sudo ./goodix-probe --bisect --read-state`: the health check has to pass. This is the
   procedure that brought the EC out of the stuck handshake in Run 16 (2026-09-30). The old one (charger
   unplugged, ~30 s) did not in Run 14, and ten days of reboots did not either (`docs/protocol.md`,
   "Recovering the EC").
5. After booting: `journalctl -k -b -1 | grep -E "goodix-probe|i8042|atkbd|usb 1-4"`.

## If the health check fails: `--read-state`

A cold power cycle does not reliably reset this EC (`docs/protocol.md`, "Recovering the EC"). If a run
stops at the health check, find out what state the EC is in before trying any fix:

```sh
sudo ./goodix-probe --bisect --read-state
```

The run is the usual baseline and attach, then the `0xa8` health check. If `0xa8` goes unanswered, the
probe sends **one** `0xae` and nothing else. That is the only command the stuck EC answered in Run 12, and
the keyboard survived it. The probe prints a `VERDICT` line, then exits 1
without sending a single step. Its reading:

| `0xae` reply | meaning | next |
|---|---|---|
| status `0x08`, counter above `0x14` | Run 12's stuck handshake is still there; the reset did not reach the EC | a deeper reset, "Recovering the EC" items 2–4 |
| counter below `0x14` | the EC *was* reset, and still ignores `0xa8` | stop and record the reply; this is new |
| no reply at all | worse than Run 12 | send nothing more; battery disconnect |

Run it again after every reset attempt: the counter is what shows whether an attempt worked. If the
health check passes, `--read-state` does nothing, and the run carries on with its steps as usual.

## `0xe4` — question closed, and what `--allow-e4` does now

**Run 4 (2026-09-19 22:41) answered this. Do not run the empty frame again — and you no longer can.**

The run sent attach, then `0xe4` with an empty payload and nothing else. The EC acknowledged it after
4 ms, went silent, and the internal keyboard died; recovery took a cold power cycle. So `0xe4` wedges
the EC on its own: neither `nop` nor `0xa8` is a precondition. Full write-up: `docs/protocol.md`, Run 4.

What is fatal is the **empty payload**, not the opcode. Since then:

- Every opcode carries a registered payload rule, and the transport refuses a payload that violates it.
  `Send(0xe4, nil)` now fails with `ErrRefused` wrapping `proto.ErrPayload`, before a byte is written.
  `TestSendRefusesTheFrameThatWedgedTheEC` in `internal/transport` is the regression test.
- `--allow-e4` still exists, and still lifts the safe ceiling for that one opcode and nothing else. But
  it now sends the **vendor's** frame:

  ```
  a0 0c 00 ac e4 09 00 03 00 02 bb 00 00 00 00 fd
                 ^^^^^^^^^^^ data_type 0xbb020003 LE, then a uint32 length of 0
  ```

  The Windows driver sends exactly this in all eight of its inits and gets an ACK plus 41 bytes back.

**Run live and confirmed — Run 5 through Run 8, 2026-09-20** (see `docs/protocol.md`). Steps 1 and 2
(`0xa8`, `0xae`) each passed twice, and then Run 8 sent `a8,ae,e4` with the vendor payload: `0xe4`
returned an ACK and a 41-byte reply, and the internal keyboard stayed alive. The expectation held — the
payload, not the opcode, is what wedges the EC. The empty form remains refused by the transport, so the
only `0xe4` that can go out is the vendor one.

The reply carries a hash of the device's PSK. Keep it out of the repo and out of any issue report.

Rehearse offline first:

```sh
./goodix-probe --bisect --replay --allow-e4 --steps e4
```

The replay answers with the ACK that Runs 1, 2 and 4 all saw and nothing after it. It deliberately does
not invent the 41 bytes; only a live run or a Windows capture can supply them.

## `0xa2` reset and reading the chip ID — what `--allow-a2` does

Run 9 (2026-09-20) sent `0x82` (`read_register`) with the vendor's chip-ID payload but **without** the
`0xa2` reset the vendor sends immediately before it, and read `01 00 80 1b` — a pre-reset value, not the
chip ID `0x2504`. So the chip-ID register is populated by the reset. `--allow-a2` admits `0xa2` to a
bisect run so the reset can precede the read:

```sh
sudo ./goodix-probe --bisect --allow-a2 --steps a8,ae,a2,82,a6
```

`0xa2` is `ClassStateChanging`, not secret-bearing and not destructive, but it changes sensor state and
may drop the EC's TLS session, so it is unlocked deliberately, the way `0xe4` is. It goes out with the
vendor payload `01 14` and is answered with an ACK; the vendor log records a small data reply (`01 00 08`).
The following `0x82` should then read `a2 04 25 00` — chip ID `0x2504`. `0xa6` (`read_otp`) is already
`ClassSafe`, so it needs no flag, **but its reply is the device OTP — the first 32 bytes are the
`sensorid`. Keep it out of the repo and out of any issue report, exactly like the `0xe4` PSK hash.**

Rehearse offline first:

```sh
./goodix-probe --bisect --replay --allow-a2 --steps a8,ae,a2,82,a6
```

## `--tls` — the TLS-PSK handshake (PLAN.md Phase 5b)

This is the step the project turns on: **does the EC accept the PSK recovered from Windows?**

`--tls` runs as the tail of a bisect run, not as a mode of its own, so it inherits everything above — one
command per step, the initial health check and the flushed log. Host counters are logged after
the bridge, including on failure; keyboard health is not checked automatically. The bridge sends
`0xd0` itself, at the moment it can catch the EC's ClientHello, so **do not
put `d0` in `--steps`**: the step loop drains the device after every command and would throw the hello
away. The probe refuses that combination rather than letting it happen.

```sh
# 1. Recover the PSK first, if it is not already there (docs/dpapi-runbook.md).
#    It must be the raw 32 bytes, and it must stay in gitignored captures/.
./goodix-dpapi -sys … -sec … -mkdir … -blob …/Goodix_Cache.bin -goodix -out captures/goodix-psk.bin

# 2. Rehearse offline. No device is opened; the "EC" is an in-process OpenSSL
#    client wearing Goodix framing. Both ends use synthetic keys; no device key is read.
./goodix-probe --bisect --replay --tls \
  --allow-d0 --allow-d4 --steps a8

# 3. Rehearse the failure too, so its output is familiar before it matters.
./goodix-probe --bisect --replay --tls \
  --allow-d0 --steps a8 --rehearse-rejection

# 4. Live, with an external keyboard attached. Steps first, then the bridge.
#    The steps are the vendor's init before 0xd0, in its order, 0xe4 included.
sudo ./goodix-probe --bisect --tls --psk captures/goodix-psk.bin \
  --allow-96 --allow-e4 --allow-a2 --allow-70 --allow-98 --allow-90 --allow-d0 --allow-d4 \
  --steps 96,a8,ae,e4,a2,82,a6,a2,70,98,90
```

Read the result off the last lines:

- **`handshake complete`** — the EC accepted the key. Phase 5b is answered, and 5c is next.
- **`THE EC DID NOT ACCEPT THIS PSK`** — the PLAN.md Phase 5b wall. The probe prints the fallbacks; take
  them in the order given, and record the alert in `docs/protocol.md` first.
- **`did not complete in time`** — the probe reads the record counts and says which of three things
  happened: the EC never started a handshake (`0 record(s) to the host` — that points at the init, not the
  key), the host never answered, or **the EC started one and went quiet after the server flight**, which is
  what Run 11 did.

### What Runs 11 and 17 found

Run 11 (2026-09-20) got the init through live and the EC opened a handshake, then stalled after the
host's ServerHello and ServerHelloDone. Run 17 (2026-09-30) sent the vendor's full init, `0xe4` included,
and got one message further: the EC sent its ClientKeyExchange, then stalled. Both times a zero-length
transfer came 256 ms after the EC's last chance to speak, and no alert either way.

The cause was the bridge (`docs/protocol.md`, Run 17). At exactly the moment the EC sends its next record,
1 ms after ServerHelloDone and 22 ms after its ClientKeyExchange, the bridge was waiting 250 ms on openssl
and not reading the device. The vendor driver always keeps a read pending. The bridge now keeps reading
the EC until its flight is finished, and sends the server's first flight as soon as ServerHelloDone is
out. The framing is the vendor's: one `0xb0` pack per record, as the driver log shows.

The one-pack-per-flight framing tried after Run 11 (`--tls-coalesce-flight`) was removed once Run 18
completed a handshake with one pack per record.

Handshake records are now logged in **full hex**, both directions. That is deliberate and it is bounded by
record type: a handshake, change-cipher-spec or alert record carries key agreement, a MAC or a reason code,
never an image and never the PSK, while application data — the one type that carries a fingerprint — is
never logged at any point. It matters because Run 11's stall could only be reproduced offline against
openssl thanks to the EC's ClientHello being in the log, and the next flight will be larger than the
transport's 64-byte hex dump.

**Keep the log for a stalled run.** It is the transcript, and it is what makes the failure reproducible
without the device.

**Then reset the EC (charger plugged in, 40 s hold; "If the keyboard stops", step 4), before doing anything
else with the device.** A stalled handshake leaves the EC
answering nothing but `0xae`, and the next run's health check will refuse to start until the EC is back. This
is the single most expensive lesson of 2026-09-20: see Run 12 in `docs/protocol.md`.

Two things the rehearsal cannot tell you, because it is openssl and not an embedded controller: whether
the EC accepts the key, and how long it holds a record the host has not read yet.
What it checks is our side: framing, sequencing, image decoding, and refusals using synthetic keys.
For live runs the key file and effective TLS policy are validated before USB is opened.
A local policy refusal stops the run without USB writes; the tools never lower the security level automatically.

Note the PSK is passed as a **path**, never as hex on the command line: an argument lands in the shell
history and in `ps` output. The in-process TLS endpoint keeps the key out of process arguments and environment.
The log records only that the endpoint was preflighted. Capture files are atomically replaced with mode `0600`;
under sudo they are assigned to the invoking user before publication. Existing symlink targets are not followed.

## `--capture` — one real frame (PLAN.md Phase 5c)

With the handshake up, `--capture` asks for a frame with `0x20`, decrypts it, and writes a PGM:

```sh
sudo ./goodix-probe --bisect --tls --psk captures/goodix-psk.bin --capture captures/frame-1.pgm \
  --allow-96 --allow-e4 --allow-a2 --allow-70 --allow-98 --allow-90 --allow-d0 --allow-d4 --allow-20 \
  --steps 96,a8,ae,e4,a2,82,a6,a2,70,98,90
```

**The output is biometric data.** It is written `0600`, `.gitignore` covers `*.pgm` and `captures/`, and it
must never go into an issue report.

The number to write down is the **plaintext length**. 7680 bytes means bare packed samples; 7693 means
upstream's 8-byte header and 5-byte trailer around them. The 7744-byte record seen on the wire is
consistent with both, so this run is what settles it (`docs/protocol.md`, "How big is an image, really").
Anything else, and the probe refuses to guess an offset — a frame decoded from the wrong offset still
looks like a fingerprint, so the mistake would not show in the picture. Record the length either way.

Rehearse it first; the stand-in sends a synthetic gradient, so the PGM from a rehearsal is a ramp, not a
fingerprint:

```sh
./goodix-probe --bisect --replay --tls \
  --allow-d0 --allow-d4 --allow-20 --steps a8 --capture /tmp/rehearsal.pgm
```

## `--wait-finger` — capture on touch (PLAN.md Phase 5d)

`--wait-finger` replaces "take a frame now" with the vendor's loop, once round: arm finger-down (`0x32`),
wait for the touch, take the frame (`0x20`), arm finger-up (`0x34`), wait for the lift. The thresholds
in both arms are computed from the EC's own readings, the way the vendor computes them
(`docs/protocol.md`, "Finger detection: where the thresholds come from"). Neither arm can be a `--steps`
entry, because neither has a fixed payload.

```sh
sudo ./goodix-probe --bisect --tls --psk captures/goodix-psk.bin --capture captures/frame-2.pgm \
  --wait-finger --finger-timeout 30s \
  --allow-96 --allow-e4 --allow-a2 --allow-70 --allow-98 --allow-90 --allow-d0 --allow-d4 --allow-20 \
  --allow-32 --allow-34 --steps 96,a8,ae,e4,a2,82,a6,a2,70,98,90
```

Keep the finger **off** the sensor until the log says `>>> TOUCH THE SENSOR`, and lift it when it says
`>>> LIFT THE FINGER`. What to write down:

- whether the first arm drew a **base-invalid** event (header `80 00 00 00`) and how many re-arms it took;
- the down event's **flags** (`0x3f` = all six zones) and the six readings, down and up — they are
  capacitance per zone, not an image, and fine to record;
- whether the frame looks like Run 20's.

Run 21 ran this command live and worked (`docs/protocol.md`). To test what it left open, **rest the
finger for a few seconds** before you lift it, so that the up arm has a finger to wait for.

If no finger-up event arrives in time the run still succeeds — the frame is already written — and the EC
is left armed for the lift, which is also where the vendor leaves it. The drain picks the event up if it
comes late.

**`captures/` is on NTFS here**, which ignores the `0600` the probe asks for. For a biometric file, a path
on a Linux filesystem (e.g. `~/goodix-captures/`) keeps the permission.

Rehearse it first. The stand-in answers the first arm with a base-invalid event and the second with a
finger-down, both taken from `dump.pcapng`, so the re-arm path runs too:

```sh
./goodix-probe --bisect --replay --tls \
  --allow-d0 --allow-d4 --allow-20 --allow-32 --allow-34 --steps a8 \
  --capture /tmp/rehearsal.pgm --wait-finger --finger-timeout 3s
```

## `--touches` — several prints in one session (PLAN.md Phase 6)

Every run so far took one frame per TLS session and exited. A driver cannot: libfprint asks for about
five prints to enrol a finger, all in one open session. `--touches N` runs the `--wait-finger` loop N
times after one handshake. Each down arm after the first is derived from the previous lift's readings,
as the vendor does, and frame N goes to `FILE-N.pgm`.

```sh
mkdir -p ~/goodix-captures
sudo ./goodix-probe --bisect --tls --psk captures/goodix-psk.bin --capture ~/goodix-captures/touch.pgm \
  --wait-finger --touches 3 --finger-timeout 30s \
  --allow-96 --allow-e4 --allow-a2 --allow-70 --allow-98 --allow-90 --allow-d0 --allow-d4 --allow-20 \
  --allow-32 --allow-34 --steps 96,a8,ae,e4,a2,82,a6,a2,70,98,90
```

Touch when the log says `>>> TOUCH THE SENSOR`, **keep the finger there** until it says `>>> LIFT THE
FINGER` (about half a second later), and lift. Use a slightly different spot each time. What to write
down:

- whether the **second** `0x20` returns a frame at all — this is the question of the run;
- whether any later down arm drew a base-invalid event;
- for each touch, how long the lift event took after the up arm (Run 21's came 34 ms after, because the
  finger was already off);
- whether the frames differ as the touches did.

Run 22 ran this command live and worked: three frames, three lifts, keyboard alive
(`docs/protocol.md`). The frames and the log are now handed to the user who ran `sudo`; before that fix
they were root-owned `0600` (`sudo chown $USER ~/goodix-captures/*` fixes older ones).

If a touch gets no lift event in time, the run stops there — the next down arm cannot go out while the
EC waits for a lift — and the frames taken so far are kept. Rehearse first with `just rehearse-touches`.

## Afterwards

- Append the run to `docs/protocol.md` as the next "Run N" — Run 21 is the latest. Include the log and the
  step that failed, or "all passed", and note whether the boot before it was cold or warm and whether
  attach produced the unsolicited `0x32`.
- If step N failed, the next run can confirm it in isolation, e.g. `sudo ./goodix-probe --bisect --steps a8`
  (attach still runs first). If **attach** failed, stop: every command is moot until attaching is
  understood.
- Logs and usbmon captures stay out of git (`.gitignore` covers `goodix-bisect-*.log` and
  `usbmon-*.txt`).
