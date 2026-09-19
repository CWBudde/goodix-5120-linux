# Bisect runbook: which step stops the keyboard?

Run 1 (2026-08-17) killed the internal keyboard, but the kernel logged nothing when it happened
(FINDINGS.md, "What the journal shows"). So nobody knows whether attaching to the device, `nop`,
`firmware_version` (`0xa8`) or `preset_psk_read` (`0xe4`) did it. `goodix-probe --bisect` finds out:
it performs one step at a time and asks for a key press on the internal keyboard after each.

This is a **live hardware run**. It is the user's decision (made 2026-09-19) to run it before a
vendor-driver capture exists, which departs from the Phase 4 gate in PLAN.md. Claude does not run it.

## What the probe does

| Step | Action | Sends |
|---|---|---|
| baseline | keyboard check only | nothing (the device is not opened) |
| 0 attach | open + claim the USB interface, drain | nothing |
| 1 | `nop` (`0x00`), collect, drain | 1 frame |
| 2 | `firmware_version` (`0xa8`), collect, drain | 1 frame |
| 3 | `preset_psk_read` (`0xe4`), collect, drain | 1 frame |

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

## Afterwards

- Append the run to `docs/protocol.md` as "Run 2" (and so on). Include the log and the step that failed,
  or "all passed".
- If step N failed, the next run can confirm it in isolation, e.g. `sudo ./goodix-probe --bisect --steps a8`
  (attach still runs first). If **attach** failed, stop: every command is moot until attaching is
  understood.
- Logs and usbmon captures stay out of git (`.gitignore` covers `goodix-bisect-*.log` and
  `usbmon-*.txt`).
