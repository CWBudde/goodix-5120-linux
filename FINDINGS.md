# Findings: Goodix `27c6:5120` on a Huawei MateBook

Everything established on 2026-08-17, in one session. Read this before running anything in this
repository.

---

## Summary

Four read-only commands reached the device and it answered correctly. Three things came out of that:

1. **The device speaks the Goodix 51x0 "wrapped" protocol.** Every frame it returned decodes cleanly
   and every checksum verifies. The framing transcribed from upstream is correct.
2. **It is not the Goodix sensor MCU.** It identifies as `GF_ITE_EC_20063` — an **ITE embedded
   controller** acting as a bridge. Upstream's 5110 reports `GF_ST411SEC_APP_12117`.
3. **That controller also drives the internal keyboard.** The probe wedged it. The keyboard died and
   only a cold power cycle brought it back.

Point 3 outweighs points 1 and 2. The protocol work succeeded; continuing it on this hardware is
not advisable. See [The keyboard incident](#the-keyboard-incident).

---

## Hardware

| | |
|---|---|
| Machine | Huawei `HVY-WXX9`, board `M1060` |
| OS | Ubuntu 26.04 LTS, kernel 7.0.0-29-generic |
| Device | `27c6:5120`, `bcdDevice 2.00` |
| Reports itself as | `GF_ITE_EC_20063` |

```
bNumInterfaces 2
  interface 0   class 2  (Communications)   EP 0x82 IN,  8 bytes
  interface 1   class 10 (CDC Data)         EP 0x01 OUT / EP 0x83 IN, bulk, 64 bytes
```

No kernel driver binds either interface. No `/dev/ttyACM*`. The device is free for userspace libusb
access, and an unprivileged open fails with `libusb: bad access [code -3]` — present, but requiring
root.

The internal keyboard is a separate device: `AT Translated Set 2 keyboard` on `isa0060/serio0`, via
the built-in `i8042` and `atkbd` drivers (`CONFIG_SERIO_I8042=y`, `CONFIG_KEYBOARD_ATKBD=y`).

---

## Why no driver exists

| Source | Status |
|---|---|
| Ubuntu archive | `libfprint-2-tod1` ships the wrapper only; `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/` does not exist |
| Vendor TOD blob | Huawei never shipped one. The Dell and Lenovo `libfprint-2-tod1-goodix` packages cover different PIDs |
| Upstream libfprint | `goodixmoc` targets the match-on-chip `27c6:58xx`/`6xxx` parts |
| [goodix-fp-dump][dump] | Covers PID `0x5120`, but only as an **SPI-wired** part (`run_5120_spi.py` → `/dev/spidev0.0`, GPIO line 279). This machine has no `/dev/spidev*` |

`fprintd-list` reports "No devices available" on an otherwise complete stack.

**The ITE EC finding probably explains all of this.** Anyone porting upstream's 51x0 work would meet
a controller that answers the framing but is not the sensor, and whose firmware namespace is
entirely different. That is a considerably harder target than a discrete Goodix MCU.

---

## Protocol: confirmed against hardware

The framing transcribed from upstream `goodix.py` is correct. Two nested layers.

**Outer ("pack")** — `[flags:1][length:2 LE][checksum:1][payload:N]`, where
`checksum = sum(bytes[0:3]) & 0xff`.

**Inner ("message")** — `[cmd:1][length:2 LE][payload:N][checksum:1]`, where the length field is
`len(payload) + 1` and `checksum = (0xaa - sum(bytes[0 : 2+length])) & 0xff`.

All four responses validate against those rules. Worked by hand:

| Frame | Computed | Received |
|---|---|---|
| `b0 03 00 a8 01` | `0xaa - 0x15c = 0x4e` | `0x4e` ✓ |
| `a8 11 00 "GF_ITE_EC_20063\0"` | `0xaa - 0x4c8 = 0xe2` | `0xe2` ✓ |
| `32 11 00` + 16 bytes | `0xaa - 0x337 = 0x73` | `0x73` ✓ |
| `b0 03 00 e4 01` | `0xaa - 0x198 = 0x12` | `0x12` ✓ |

### Correction: the ACK convention

Upstream's documented convention — the device echoes the command byte with bit 0 set — **is wrong for
this device**, or at least for this EC.

The real acknowledgement is a distinct message with **`cmd = 0xb0`**, whose payload is
`[original_command][status]`:

```
sent 0xa8  →  b0 03 00 | a8 01 | 4e      ACK for 0xa8, status 01
sent 0xe4  →  b0 03 00 | e4 01 | 12      ACK for 0xe4, status 01
```

Note `0xb0` also names `FlagTLSData` at the *pack* layer. The two are different fields at different
levels and must not be conflated.

### Correction: two transfers per command

Each command produces **an ACK first, then a separate data response**. The probe read only once per
command, so its output lagged by one transfer — the firmware string arrived while it was reading for
`read_otp`:

| Sent | Read | Actually was |
|---|---|---|
| `nop` (`0x00`) | `cmd=0x32`, 16 B | unsolicited or stale |
| `firmware_version` (`0xa8`) | `b0 … a8 01` | ACK for `0xa8` |
| `read_otp` (`0xa6`) | `a8 … "GF_ITE_EC_20063"` | **data** for `0xa8` |
| `preset_psk_read` (`0xe4`) | `b0 … e4 01` | ACK for `0xe4` |

`read_otp` (`0xa6`) produced neither an ACK nor data. Either the EC does not implement it, or its
reply was still queued. Unresolved.

### The unsolicited `0x32` message

The first read returned a command this project has no name for:

```
32 11 00 | 02 00 2f 00 1e 01 38 01 ff 00 f7 00 3f 01 34 01 | 73
```

As little-endian `uint16`: `2, 47, 286, 312, 255, 247, 319, 308`. Plausibly sensor or DAC
configuration. It arrived before any command could have produced it, so the EC likely emits it on
attach. Unidentified.

---

## The keyboard incident

**What happened.** Immediately after the probe ran, the internal keyboard stopped working. The
`27c6:5120` device then disappeared from the USB bus entirely (`1-4` vanished from
`/sys/bus/usb/devices/`), and `usbreset` failed with `can't open [Input/output error]`.

**Why.** The ITE EC serves both the fingerprint sensor over USB and the internal keyboard over
i8042. Four read-only fingerprint commands left it in a state where it stopped servicing either.

**Recovery.** Software recovery does not work — there is no device left to reset. Unbinding and
rebinding `atkbd` on `serio0` correctly recreated the input node (`input29`), proving the Linux side
was healthy, but no scancodes arrived because the EC was not sending any.

Only a **cold power cycle** cleared it: full shutdown, charger disconnected, power button held ~30
seconds. A warm reboot does not reset the EC. Afterwards both the keyboard and `27c6:5120` returned
and remain healthy.

**The lesson, stated plainly.** This project classified opcodes by what they do *to the sensor* —
read versus write flash. That axis was correct for a discrete Goodix MCU and wrong here. The real
risk was **collateral**: commands harmless to a fingerprint MCU are not harmless to a controller that
also runs the keyboard. `read_otp` is read-only in the intended sense and still contributed to this.

The safety model did work as designed. Flash-writing opcodes were never compiled into the binary,
and nothing persisted past the power cycle. But "read-only" was the wrong safety axis for shared
silicon, and `GF_ITE_EC` announced that fact before the damage was understood.

---

## What this means for a driver

**Harder than the plan assumed.** The plan tested whether the 5120 answers the 51x0 command set. It
does — but through an EC bridge, not the sensor. So an unknown amount of the 51x0 command set may be
EC-specific, and upstream's firmware, PSK and image-capture flows target silicon that is not what
answers here.

**Do not flash anything.** Upstream `driver_51x0.main()` uploads `GF_ST411SEC_APP_12117.bin` over IAP
when the running firmware does not match. This device runs `GF_ITE_EC_20063`, so that condition
holds and upstream's own script would attempt the write. Writing ST411SEC firmware to an ITE EC that
also drives the keyboard could brick more than the sensor.

**Tier 2 is not advisable on this machine.** It requires `mcu_get_image` and a TLS session against
the controller now known to own the keyboard. The downside is no longer bounded by an unusable
fingerprint sensor.

---

## Recommendation

Stop the hands-on probing. The result is worth publishing as it stands: the framing is confirmed
against real hardware, the ACK convention is corrected, and the ITE EC bridge is identified. Posting
this to the [libfprint issue tracker][issues] and the [goodix-fp-dump][dump] repository would help
the next person, who will otherwise repeat the keyboard incident.

If anyone does continue, do it with an external keyboard attached, from a TTY, with the cold-power-
cycle recovery known in advance, and with no work open elsewhere on the machine.

---

## Repository state

| Package | Role |
|---|---|
| `internal/proto` | framing, checksums, opcode registry and safety classes |
| `internal/transport` | gousb transport, replay fake, the enforcement chokepoint |
| `internal/tlspsk` | Tier 2 scaffold — TLS-PSK via an `openssl s_server` subprocess |
| `internal/image` | Tier 2 scaffold — PGM writer and 12-bit unpacker |
| `cmd/goodix-probe` | the read-only probe |

All packages build, vet and test clean. `go list -deps ./cmd/goodix-probe` shows the probe links only
`proto` and `transport` — the Tier 2 packages are not compiled into it.

**The "one transfer behind" defect is fixed in code (2026-09-19), offline only.** The probe decodes
`0xb0` acknowledgements, reads ACK then data per command, skips unsolicited messages, drains the IN
endpoint before exiting and no longer sends `read_otp`. It is tested against the Run 1 capture through
the replay transport. **This is not a recommendation to run it.** The advice above still stands, and
`PLAN.md` Phase 4 gates any live run on a capture from the vendor driver.

### Known issues

- Live runs need root; there is deliberately no udev rule.

---

## Reference material

The 12-bit image packing and PSK details were transcribed from upstream and are recorded in
[`docs/protocol.md`](docs/protocol.md). They remain unverified against this device and should be
treated as hypotheses about a chip that is not what answered.

- [goodix-fp-linux-dev/goodix-fp-dump][dump] — the protocol knowledge this rests on
- [goodix-fp-linux-dev/libfprint][fork] — experimental driver fork, 5110 only
- [libfprint issue tracker][issues]

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[fork]: https://github.com/goodix-fp-linux-dev/libfprint
[issues]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues
