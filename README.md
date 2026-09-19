# goodix-5120-linux

Bring-up work for the **Goodix `27c6:5120`** fingerprint sensor on Linux — the reader in a Huawei
MateBook (`HVY-WXX9`), which has no working driver on any distribution.

> ## ⚠ Do not run the probe on this hardware
>
> The one live run **wedged the embedded controller and killed the internal keyboard.** Only a cold
> power cycle recovered it — a warm reboot does not.
>
> The device identifies as `GF_ITE_EC_20063`: an **ITE embedded controller** that bridges to the
> sensor *and* drives the internal keyboard over i8042. Commands harmless to a fingerprint MCU are
> not harmless here.
>
> **Read [`FINDINGS.md`](FINDINGS.md) first.** It records what was established, and why the
> recommendation is to stop.

## Why this exists

The sensor is unsupported everywhere:

| | |
|---|---|
| Ubuntu archive | `libfprint-2-tod1` is only the wrapper; `/usr/lib/x86_64-linux-gnu/libfprint-2/tod-1/` does not exist |
| Vendor TOD blob | Huawei never shipped one; the Dell/Lenovo `libfprint-2-tod1-goodix` packages cover different PIDs |
| Upstream libfprint | `goodixmoc` targets the match-on-chip `27c6:58xx`/`6xxx` parts, not this one |

`fprintd-list` reports **"No devices available"** on an otherwise complete stack (`fprintd` 1.94.5,
`libfprint-2-2`, `libpam-fprintd` all installed).

The upstream reverse-engineering project [goodix-fp-dump][dump] *does* cover PID `0x5120` — but only
as an **SPI-wired** part (`run_5120_spi.py` → `/dev/spidev0.0` + `gpiochip0` line 279). This machine
has no `/dev/spidev*` at all.

## The hypothesis under test

This machine's sensor is **USB-attached**:

```
idVendor 0x27c6  idProduct 0x5120   bcdDevice 2.00
  interface 0: class 2  (Communications)  EP 0x82 IN, 8 bytes
  interface 1: class 10 (CDC Data)        EP 0x01 OUT / EP 0x83 IN, bulk, 64 bytes
```

No kernel driver is bound to either interface, so it is free for userspace libusb access.

Upstream separates transport from command layer, and the USB-side sibling `driver_51x0.py` — used by
`run_5110.py`, which is literally `driver_51x0.main(0x5110)` — targets the same **51x0 /
MILAN_ST411SEC** family.

> **If the 5120 answers the 51x0 command set over USB bulk, the whole stack becomes reachable.**

Confirming or refuting that, cheaply and without risking the hardware, was the entire goal of this
increment.

**Answered: it does answer, but the reachable thing is not the sensor.** What responds is an ITE
embedded controller shared with the keyboard. The framing assumption held; the "without risking the
hardware" half did not. See [`FINDINGS.md`](FINDINGS.md).

## Safety

`driver_51x0.main()` upstream will flash `GF_ST411SEC_APP_12117.bin` — **5110** firmware — over IAP if
the chip is not already running expected firmware. Writing that to a **5120** could brick the sensor
permanently.

So the guarantee here is structural, not a promise to be careful:

1. **Opcodes carry a safety class.** `ClassSafe` (read-only) · `ClassStateChanging` (alters runtime
   state, no flash write) · `ClassDestructive` (can write flash).
2. **The transport is the chokepoint.** `Send` refuses any opcode whose class exceeds the configured
   ceiling — default `ClassSafe` — and refuses unregistered opcodes outright. The refusal happens
   before any byte reaches the device.
3. **Destructive opcodes are not in the binary.** `write_firmware` (`0xf0`) and `preset_psk_write`
   (`0xe0`) are registered only behind the `goodix_destructive` build tag. A unit test asserts the
   default build cannot name them.
4. **Opcodes carry a payload rule, and the transport enforces it.** Each opcode records the payload
   length the Windows driver was observed to send; `Send` refuses anything else, before a byte is
   written. This is not theoretical tidiness. An `0xe4` with an *empty* payload wedged the embedded
   controller and killed the laptop's internal keyboard three times, while the vendor's `0xe4` with
   its 8-byte argument is answered normally. That frame can no longer be built.
5. **No firmware blob is vendored** into this repository.
6. **Nothing but the probe can reach the device.** `cmd/goodix-pcap` reads capture files and imports
   only `internal/proto`; a test parses the source to prove it cannot import a USB library.

## Requirements

- Go 1.26+
- `libusb-1.0-0-dev` (`sudo apt install libusb-1.0-0-dev`)
- Root for live runs — there is deliberately no udev rule yet, so an unprivileged run fails with
  `libusb: bad access [code -3]`

## Usage

Offline only. Both of these are safe — neither opens the device:

```sh
go build -buildvcs=false ./cmd/goodix-probe

./goodix-probe --dry-run     # decode and print the frames it would send; opens no USB device
./goodix-probe --replay      # exercise the full decode path against a scripted fake
```

The live mode (`sudo ./goodix-probe -v`) is what wedged the embedded controller. It still exists, and
is still read-only in the sense the safety model means, but read [`FINDINGS.md`](FINDINGS.md) before
using it — and expect to need a cold power cycle.

Note also that the probe reads **one transfer per command**, while the device sends two (ACK, then
data), so its output runs one behind. That is deliberately left unfixed; fixing it would invite
another run.

## Findings

*Populated as the probe runs. See [`docs/protocol.md`](docs/protocol.md) for raw frame captures.*

One live run, 2026-08-17. Raw capture in [`docs/protocol.md`](docs/protocol.md); full account in
[`FINDINGS.md`](FINDINGS.md).

| Question | Answer |
|---|---|
| Does the 5120 respond on bulk EP 0x01/0x83? | **Yes** |
| Does the 51x0 framing decode? | **Yes** — all four checksums verify by hand |
| Does it ACK per the `cmd \| 0x01` convention? | **No** — ACK is a `0xb0` message carrying `[cmd][status]` |
| Does `firmware_version` (`0xa8`) return a plausible string? | **Yes** — `GF_ITE_EC_20063` |
| Does `read_otp` (`0xa6`) return sane data? | No reply at all — unimplemented or still queued |
| What is it? | An **ITE embedded controller**, not the Goodix sensor MCU |
| Sensor resolution | Still unknown. Upstream `driver_51x0.py` declares 80x88 for different silicon |

**Verdict: the protocol assumption held, and the conclusion is still to stop.** The framing is
confirmed, but it is answered by a controller that also drives the keyboard — which the probe wedged.
Tier 2 would need `mcu_get_image` and a TLS session against that same controller.

## Layout

```
cmd/goodix-probe/     Tier 1 entry point — the only thing that opens a device
cmd/goodix-pcap/      offline reader for USBPcap captures; cannot reach hardware
internal/proto/       packet framing, checksums, opcode registry, safety classes, payload rules
internal/transport/   gousb USB transport, replay fake, ceiling + payload enforcement
internal/capture/     pcapng and USBPcap decoding (stdlib + proto only)
internal/tlspsk/      Tier 2 scaffold — TLS-PSK via openssl subprocess (no call sites)
internal/image/       Tier 2 scaffold — PGM writer (no call sites)
docs/protocol.md      observed wire format, appended as we learn
```

## Roadmap

- **Tier 1** — read-only probe. **Done.** The protocol decodes; the device is an EC bridge.
- **Tier 2** — IAP check → PSK → TLS → `mcu_get_image`. The scaffold exists and is not linked into
  any binary. **Not recommended on this hardware** — it would drive the controller that owns the
  keyboard, and upstream's IAP path would try to flash ST411SEC firmware onto an ITE EC.
- **Tier 3** — a real [libfprint][libfprint] driver so `fprintd` and PAM work. **Must be C** —
  libfprint is C/GLib. Out of scope, and blocked behind Tier 2 regardless.

The useful next step is not code. It is posting these findings to the
[libfprint issue tracker][issues] and [goodix-fp-dump][dump], so the next person to try this does not
repeat the keyboard incident.

## Credit

The protocol knowledge comes from [goodix-fp-linux-dev/goodix-fp-dump][dump] and the associated
[libfprint fork][fork]. This project is an independent Go re-implementation for a USB-attached 5120,
which upstream does not cover.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[fork]: https://github.com/goodix-fp-linux-dev/libfprint
[libfprint]: https://gitlab.freedesktop.org/libfprint/libfprint
[issues]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues

## Licence

Not yet chosen. Upstream goodix-fp-dump is GPL-licensed; if any code is ported rather than
reimplemented from the protocol description, that constrains the choice here.
