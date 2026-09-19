# Bisect runbook: which step stops the keyboard?

Run 1 (2026-08-17) killed the internal keyboard, but the kernel logged nothing when it happened
(FINDINGS.md, "What the journal shows"). So nobody knows whether attaching to the device, `nop`,
`firmware_version` (`0xa8`) or `preset_psk_read` (`0xe4`) did it. `goodix-probe --bisect` finds out:
it performs one step at a time and asks for a key press on the internal keyboard after each.

**Answered by Run 2 (2026-09-19): `0xe4`.** See `docs/protocol.md`. `0xe4` has been removed from the
steps since then, so a bisect run now covers only attach, `nop` and `0xa8`.

This is a **live hardware run**. It is the user's decision (made 2026-09-19) to run it before a
vendor-driver capture exists, which departs from the Phase 4 gate in PLAN.md. Claude does not run it.

## What the probe does

| Step | Action | Sends |
|---|---|---|
| baseline | keyboard check only | nothing (the device is not opened) |
| 0 attach | open + claim the USB interface, drain | nothing |
| 1 | `nop` (`0x00`), collect, drain | 1 frame |
| 2 | `firmware_version` (`0xa8`), collect, drain | 1 frame |
| ~~3~~ | ~~`preset_psk_read` (`0xe4`)~~ — removed after Run 2 wedged the EC on it | — |

After each step it logs the i8042 interrupt counts, the ACPI SCI count and whether `27c6:5120` is still
enumerated, and then waits (30 s by default) for a key press on the **internal** keyboard. The first
missing key press stops the run. Nothing after that step is sent. The exit status is 0 if every step
passed, 2 if the keyboard stopped, and 1 on any other error.

The log goes to stdout and to `goodix-bisect-<time>.log`. The file is flushed to disk after every line.
Step markers (`goodix-probe: ...`) also go to the kernel log, so they line up with kernel messages in
`journalctl -k`. Only `ClassSafe` opcodes from the probe's step list are accepted, and `read_otp`
(`0xa6`) is not among them.

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

## Confirming `0xe4` alone (`--allow-e4`)

Run 2 sent `0xe4` after `nop` and `0xa8`, so it is still open whether `0xe4` wedges the EC **on its own**,
or only after `0xa8`. This run sends attach and then `0xe4` only. It is expected to kill the internal
keyboard, so plan it right before a shutdown you need anyway, e.g. before booting Windows for
[`windows-capture-runbook.md`](windows-capture-runbook.md). The cold power cycle then does double duty.

`0xe4` is not a probe step and the transport refuses it. `--allow-e4` is the only way to send it: it works
only with `--bisect`, admits `0xe4` in `--steps` and nothing else, and lets the transport pass exactly that
opcode above the safe ceiling. The log header says `allowed above it: preset_psk_read (0xe4)`.

1. Do "Before" steps 1–3 above (external keyboard, nothing unsaved, build).
2. Rehearse with the real keyboard and no USB:
   `sudo ./goodix-probe --bisect --replay --allow-e4 --steps e4`. It should show the replayed ACK for
   `0xe4` and pass every check when you press Shift. Delete the rehearsal log.
3. Strongly recommended: start the usbmon capture from "Before" step 5. It shows whether *anything*
   arrives after the ACK, which the probe can only report up to its timeout.
4. Run:

   ```sh
   sudo ./goodix-probe --bisect --allow-e4 --steps e4 --timeout 30s
   ```

   `--timeout 30s` gives the EC 30 s instead of 5 s to send data after the ACK, to tell "slow" from
   "never". The keyboard prompt comes after that wait, so be patient.
5. Press Shift on the **internal** keyboard at each prompt.

What the outcome means:

- **Keyboard dead after step 1 (expected):** `0xe4` wedges the EC on its own; `0xa8` is not a
  precondition. Follow "If the keyboard stops" below. The cold power cycle there is also the clean
  shutdown before Windows.
- **Keyboard alive after step 1:** `0xe4` alone is survivable, and the wedge in Run 2 needed something
  before it (`nop`, `0xa8`, or both). That's a real surprise, so stop there. Don't try other
  combinations in the same boot. Note it, and still do a cold power cycle before Windows, so the capture
  starts from a fresh EC.
- **Data after the ACK:** whatever it is, it's new. Keep the log and the usbmon file.

Record the result as Run 4 in `docs/protocol.md`, noting whether the boot before it was cold or warm and
whether attach produced the unsolicited `0x32`.

## Afterwards

- Append the run to `docs/protocol.md` as "Run 2" (and so on). Include the log and the step that failed,
  or "all passed".
- If step N failed, the next run can confirm it in isolation, e.g. `sudo ./goodix-probe --bisect --steps a8`
  (attach still runs first). If **attach** failed, stop: every command is moot until attaching is
  understood.
- Logs and usbmon captures stay out of git (`.gitignore` covers `goodix-bisect-*.log` and
  `usbmon-*.txt`).
