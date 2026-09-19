# Bisect runbook: which step stops the keyboard?

Run 1 (2026-08-17) killed the internal keyboard, but the kernel logged nothing when it happened
(FINDINGS.md, "What the journal shows"). So nobody knows whether attaching to the device, `nop`,
`firmware_version` (`0xa8`) or `preset_psk_read` (`0xe4`) did it. `goodix-probe --bisect` finds out:
it performs one step at a time and asks for a key press on the internal keyboard after each.

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
| baseline | keyboard check only | nothing (the device is not opened) |
| 0 attach | open + claim the USB interface, drain | nothing |
| 1 | `firmware_version` (`0xa8`) with payload `00 00`, collect, drain | 1 frame |
| ~~2~~ | ~~`nop` (`0x00`)~~ — dropped; the vendor never sends it to an ITE EC | — |
| ~~3~~ | ~~`preset_psk_read` (`0xe4`)~~ — removed after Run 2 wedged the EC on it | — |

After each step it logs the i8042 interrupt counts, an **EC refresh counter** and whether `27c6:5120` is still
enumerated, and then waits (30 s by default) for a key press on the **internal** keyboard. The first
missing key press stops the run. Nothing after that step is sent. The exit status is 0 if every step
passed, 2 if the keyboard stopped, and 1 on any other error.

The log goes to stdout and to `goodix-bisect-<time>.log`. The file is flushed to disk after every line.
Step markers (`goodix-probe: ...`) also go to the kernel log, so they line up with kernel messages in
`journalctl -k`.

`--steps` accepts an opcode only when it is `ClassSafe` **and** its payload is on record from the vendor
driver — today `a8`, `ae`, `82` and `a6`. That is how PLAN.md Phase 4 adds one command per live run
without widening what the plain probe sends. It cannot name a state-changing opcode, so the run fails
before the device is opened rather than halfway through.

## Before

1. Plug in an **external USB keyboard** and check that it types. After a wedge, you need it to shut down.
2. Save and close everything else.
3. Build: `go build -buildvcs=false ./cmd/goodix-probe`
4. **Rehearse without USB:** `sudo ./goodix-probe --bisect --replay`. This watches the real internal
   keyboard but replays Run 1 instead of opening the device. Press Shift at every prompt and check that
   each check says "keyboard alive". Then let one prompt time out to see the failure path (exit 2).
   Delete the rehearsal log afterwards.
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

At every `>>> press Shift on the INTERNAL keyboard` prompt, press Shift on the **laptop's** keyboard, not
the external one. Shift types nothing into the terminal.

If you miss a prompt, the run stops with a false alarm. Check whether the internal keyboard still types.
If it does, note that in the log and run again.

## If the keyboard stops

1. Stop the usbmon `cat` with Ctrl-C on the external keyboard.
2. Don't try to repair it: no `usbreset`, no atkbd unbind/bind, no suspend. In Run 1 these only added
   noise, and `usbreset` is what made the device disappear from the bus.
3. Optionally, before shutting down, capture:
   `journalctl -k -b --since "-10 min" > kernel-after-wedge.txt` and `ls /sys/bus/usb/devices/`.
4. **Cold power cycle:** `systemctl poweroff`, unplug the charger, hold the power button ~30 s, then boot.
5. After booting: `journalctl -k -b -1 | grep -E "goodix-probe|i8042|atkbd|usb 1-4"`.

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

**This has not been run live.** PLAN.md Phase 4 step 3 plans it, after steps 1 and 2 have passed twice,
with an external keyboard attached. The expectation is now the **opposite** of what this section used to
say: an ACK and 41 bytes, and a keyboard that keeps working. A dead keyboard would mean the vendor log is
not the whole story, so stop and record it.

The reply carries a hash of the device's PSK. Keep it out of the repo and out of any issue report.

Rehearse offline first:

```sh
./goodix-probe --bisect --replay --assume-keys --allow-e4 --steps e4
```

The replay answers with the ACK that Runs 1, 2 and 4 all saw and nothing after it. It deliberately does
not invent the 41 bytes; only a live run or a Windows capture can supply them.

## Afterwards

- Append the run to `docs/protocol.md` as the next "Run N" — Run 4 is the latest. Include the log and the
  step that failed, or "all passed", and note whether the boot before it was cold or warm and whether
  attach produced the unsolicited `0x32`.
- If step N failed, the next run can confirm it in isolation, e.g. `sudo ./goodix-probe --bisect --steps a8`
  (attach still runs first). If **attach** failed, stop: every command is moot until attaching is
  understood.
- Logs and usbmon captures stay out of git (`.gitignore` covers `goodix-bisect-*.log` and
  `usbmon-*.txt`).
