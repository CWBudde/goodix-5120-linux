# ACPI: what the firmware says about the EC, the keyboard and the sensor

Read on 2026-09-20 from this machine (`HVY-WXX9`, board `HVY-WXX9-PCB`, BIOS `1.08`, EC firmware
release `1.8` from `/sys/class/dmi/id/ec_firmware_release`):

```sh
sudo acpidump > tables.dat && acpixtract -a tables.dat && iasl -d dsdt.dat ssdt*.dat
```

DSDT plus 13 SSDTs. **Tables were only read; no ACPI method was called**, and the dump is not in the
repo. Everything below is observed in the disassembly unless marked otherwise.

## The short answer

**Nothing in ACPI can reset the EC, power-cycle the sensor, or cut power to its USB port.** The cold
power cycle stays the only recovery. That was the open question in PLAN.md Phase 3, and it is closed.

## Three host interfaces on one ITE part

| interface | ACPI object | address | serves |
|---|---|---|---|
| i8042 keyboard | `\_SB.PCI0.LPC0.KBC0`, `_HID FUJ7401`, `_CID PNP0303` | I/O `0x60`/`0x64`, IRQ 1 | the internal keyboard |
| ACPI EC | `\_SB.PCI0.LPC0.EC0`, `_HID PNP0C09`, `_GPE 3` | `_CRS` claims I/O `0x62`/`0x66` | battery, lid, thermal, Fn keys |
| USB CDC | `\_SB.PCI0.GP17.XHC0.RHUB.PRT4` | PCI `0000:04:00.3` port 4 = Linux `1-4` | the fingerprint sensor |

Three independent host interfaces into one chip, on different ports with different interrupts. That
is the shape of the keyboard incident: a USB command blocks the EC firmware, and the keyboard
interface goes silent with it although nothing touched `0x60`/`0x64`.

## The sensor's USB port is described, and nothing more

`XHC0` is `_ADR 0x03` under `GP17` (`_ADR 0x00080001`) → PCI `0000:04:00.3` → Linux `usb1`.
`XHC1` is `_ADR 0x04` → `0000:04:00.4`, and its `PRT4` carries a `CAM1` child — the webcam, `3-4`.
So the reader is **XHC0's `PRT4`**, which in full is:

```asl
Device (PRT4)
{
    Name (_ADR, 0x04)
    Method (_UPC, 0, Serialized) { Return (GUPC (0xFF, 0xFF)) }
    Method (_PLD, 0, Serialized) { Return (GPLD (Zero, 0x04)) }
}
```

`_UPC (0xFF, 0xFF)` and `_PLD (Zero, …)` mark it as an internal, non-user-visible port. There is
**no `_PRW`, no `_PR0`/`_PS0`/`_PS3`, no `PowerResource` and no `_DSM`**. The firmware has no way to
drop power to that port or to assert a reset line on the sensor, and neither does a driver.

## The EC's own interfaces

Two `SystemMemory` regions inside `EC0`, not the classic `0x62`/`0x66` handshake the `_CRS` advertises:

- **`ERAM` at `0xFE800700`, 0xFF bytes** — EC RAM, mapped straight into memory. Holds the EC version
  bytes (`ECMV`, `ECSV`, `ECTV`, `ECRV`), Fn-lock and Fn state, lid (`LSTE`, `LID2`), ten thermal
  bytes (`TP00`…), SMBus pass-through (`SMPR`, `SMAD`, `SMCM`, `SDA0`, `SDA1`), the whole battery
  block (`BAPR`, `BARC`, `BAPV`, `BFCC`, `BTEM`, …), a watchdog period (`WDTL`/`WDTH`) and flags
  `HWF0`–`HWF5`.
- **`SMA2` at `0xFE800800`, 0x80 bytes** — a command mailbox: `CMDB`, `STAT`, `NUMB`, `DAT0`–`DAT2`.

The ASL uses three commands: `0x80` reads a byte of EC address space (`RDER`), `0x29` then `0x81`
writes one (`WTER`), and `ECCC (cmd, d0, d1, d2)` is a **generic pass-through that will send any
command byte**. The EC's command set itself is firmware, not described here. Each call spins on
`CMDB` clearing, 256 × 2 ms, so against a wedged EC these return `0xFF` after about half a second
rather than hanging.

**Do not call these.** `ECCC` is an unfiltered command channel into the part that also runs the
keyboard — the same class of mistake as the empty `0xe4`, one layer down.

## The watchdog is not a way out

`HWWD` (`_HID WDT0001`) is an EC watchdog: `OWDT` starts it (`HWF1`, `HWF0` = 1), `CWDT` stops it,
`SWDT` sets the period, `FWDT` feeds it. It resets the *system*, not the EC's USB task, and it is a
service of the very firmware that is stuck. Not a recovery path.

## Nothing in ACPI knows about a fingerprint reader

A search of the DSDT and all 13 SSDTs finds no `fingerprint`, `Goodix`, `FPRT`-style name. The reader
is a plain USB device; the firmware knows only which port it sits on. So there is no vendor power
sequencing to imitate and nothing for a Linux driver to hook.

## What this changes for the bisect runbook

**The ACPI SCI counter is not a liveness signal for the EC.** `--bisect` logs it after every step, but
it stood still at 300 through all of Run 2 and at 118 through both 18:2x runs — healthy runs, every
one. It cannot tell a live EC from a wedged one, and Run 4's 328 → 330 → 330 says nothing either.

A better probe, and free: the battery. `_BST` reads `BAPR`/`BARC`/`BAPV` **directly out of `ERAM`**,
so it is a plain memory read of RAM the EC keeps up to date — it will not fail when the EC is stuck,
it will freeze. `/sys/class/power_supply/BAT0/voltage_now` and `current_now` are world-readable and
move on their own on a live machine. Logging them at each keyboard check, and watching whether they
still move after a wedge, would show whether the wedge is confined to the EC's USB task or has taken
the whole firmware down. Not implemented yet — it touches the live path, so it is the user's call.
