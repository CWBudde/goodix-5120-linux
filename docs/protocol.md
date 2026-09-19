# Goodix 51x0 wire protocol — as understood for `27c6:5120`

Working notes. Two kinds of statement appear here and they are deliberately kept apart:

- **Transcribed** — read from the upstream [goodix-fp-dump][dump] Python source (`goodix.py`,
  `protocol.py`, `driver_51x0.py`). Believed accurate for the 5110; *assumed* to hold for the 5120.
- **Observed** — measured against this machine's actual hardware. Nothing is observed yet.

Anything not marked observed is a hypothesis. The point of the probe is to move lines from the first
category to the second.

## Hardware facts (observed)

From `lsusb -v -d 27c6:5120` on the target machine:

```
idVendor      0x27c6
idProduct     0x5120
bcdDevice     2.00
bNumInterfaces 2

interface 0   bInterfaceClass 2   Communications
              bNumEndpoints   1
              EP 0x82 IN      wMaxPacketSize 0x0008

interface 1   bInterfaceClass 10  CDC Data
              bNumEndpoints   2
              EP 0x01 OUT     wMaxPacketSize 0x0040   bulk
              EP 0x83 IN      wMaxPacketSize 0x0040   bulk
```

Also observed:

- No kernel driver bound to either interface — no `/dev/ttyACM*`, and the `driver` symlinks under
  `/sys/bus/usb/devices/1-4:1.{0,1}/` do not resolve.
- No `/dev/spidev*` on this system, which is why the upstream `run_5120_spi.py` path is inapplicable.
- Unprivileged `OpenDevices()` fails with `libusb: bad access [code -3]` (`LIBUSB_ERROR_ACCESS`).
  The device is present; only permission is missing.

## Framing (transcribed)

Two nested layers.

### Outer layer — "pack"

```
+--------+------------------+----------+------------------+
| flags  | length (2, LE)   | checksum | payload (N)      |
| 1 byte | = N              | 1 byte   |                  |
+--------+------------------+----------+------------------+
```

`checksum = sum(bytes[0:3]) & 0xff` — i.e. over the flags byte and both length bytes only.

| flags | meaning |
|---|---|
| `0xa0` | message protocol (the inner layer below) |
| `0xb0` | TLS-wrapped data |
| `0xb2` | TLS-wrapped data |

### Inner layer — "message"

```
+--------+------------------+-------------+----------+
| cmd    | length (2, LE)   | payload (N) | checksum |
| 1 byte | = N + 1          |             | 1 byte   |
+--------+------------------+-------------+----------+
```

The length field counts the payload **plus one** for the trailing checksum byte.

`checksum = (0xaa - sum(bytes[0 : 2+length])) & 0xff`

In *no-checksum mode* the trailing byte is the literal constant `0x88` instead of the computed value.

### ACK convention

After a command is sent, the device first replies with an acknowledgement whose command byte is the
original **with bit 0 set** (`cmd | 0x01`), before the actual response payload follows.

### Transport rules

- Outbound frames are zero-padded up to a multiple of `0x40` (64) bytes and written in 64-byte chunks.
- Reads request up to `0x10000` bytes; a short read is normal.

## Command set (transcribed)

Classification is this project's own, and drives the enforcement described in the README.

### `ClassSafe` — read-only, in the default allowlist

| Opcode | Name | Notes |
|---|---|---|
| `0x00` | `nop` | cheapest liveness check; the first thing the probe sends |
| `0xa8` | `firmware_version` | **the go/no-go signal** — a plausible string means the family assumption holds |
| `0xa6` | `read_otp` | one-time-programmable calibration data |
| `0xe4` | `preset_psk_read` | reads the stored PSK metadata; does *not* write |

### `ClassStateChanging` — alters runtime state, no flash write; opt-in only

| Opcode | Name |
|---|---|
| `0x96` | `enable_chip` |
| `0xa2` | `reset` |
| `0x70` | `mcu_switch_to_idle_mode` |
| `0x90` | `upload_config_mcu` |
| `0xd0` | `request_tls_connection` |
| `0x20` | `mcu_get_image` |
| `0xf4` | `check_firmware` |

`0xf4` is classified conservatively: it reads state, but it appears in upstream's IAP flow, and being
wrong in that direction is cheap while being wrong in the other could cost the sensor.

### `ClassDestructive` — never compiled into a default build

| Opcode | Name | Why |
|---|---|---|
| `0xf0` | `write_firmware` | flashes application firmware — **can brick the device** |
| `0xe0` | `preset_psk_write` | writes the PSK |

Registered only behind the `goodix_destructive` build tag.

## TLS-PSK layer (transcribed, Tier 2)

The 51x0 family protects image transfer with **TLS-PSK**. Go's `crypto/tls` implements no PSK cipher
suites, so upstream's workaround is mirrored here: spawn

```
openssl s_server -nocert -psk <hex> -port 4433 -quiet
```

and bridge the decrypted stream to the device. Handshake outline per upstream:

1. Client hello — 32-byte random
2. Server identity — server random + identity
3. Session key derivation — HMAC-based expansion from the PSK
4. Client done — client identity
5. Server done — confirmation

Subsequent image data uses alternating encrypted/unencrypted `0x3f0`-byte blocks with HMAC-SHA256
authentication.

PSK provenance varies across the family — sealed (hardware-specific), white-box, or all-zero. Which
applies to this 5120 is **unknown** and is a Tier 2 question.

## Open questions

| Question | How to answer |
|---|---|
| Does the 5120 accept 51x0 framing at all? | probe: `nop` → expect ACK `0x01` |
| Firmware version string | probe: `0xa8` |
| Sensor resolution | unknown for the 5120. Upstream `driver_51x0.py` declares `SENSOR_WIDTH = 80`, `SENSOR_HEIGHT = 88`. Must be measured, not assumed |
| PSK variant | see below — the TLS pre-shared key is transcribed; whether the 5120 accepts it is unverified |
| 12-bit sample packing for image decode | **resolved** — transcribed from upstream `tool.py`, see below |

## Image sample packing (transcribed, `tool.py::decode_image`)

Every 6 bytes carry 4 twelve-bit samples, in a deliberately irregular order — this is *not* a plain
little- or big-endian 12-bit stream, and assuming it were would produce a plausible-looking but
wrong image:

```
s0 = (b0 & 0x0f) << 8 | b1
s1 =  b3        << 4  | b0 >> 4
s2 = (b5 & 0x0f) << 8 | b2
s3 =  b4        << 4  | b5 >> 4
```

Corroborated by arithmetic: `driver_51x0.py` reads 10573 bytes, strips an 8-byte header and 5-byte
trailer, leaving 10560 payload bytes; 80 x 88 = 7040 samples, and 7040 / 4 * 6 = 10560 exactly.

## PSK provenance (transcribed)

Three distinct values appear upstream and conflating them wastes time:

| Value | Role |
|---|---|
| 32 zero bytes | the actual **TLS pre-shared key** passed to `openssl -psk` |
| `PSK_WHITE_BOX` | a 96-byte blob written into the device's PSK slot — *written*, hence destructive |
| `PMK_HASH` | SHA-256 the device reports back for verification |

Whether this 5120 accepts the zero key is unverified and is a Tier 2 question.

## Observed exchanges

### Run 1 — 2026-08-17, `sudo ./goodix-probe -v`

The only live run. It wedged the embedded controller and killed the internal keyboard; see
[`../FINDINGS.md`](../FINDINGS.md) before considering another.

```
transport: opened 27c6:5120 interface 1 (in 0x83, out 0x01)

TX nop (0x00)               a0 04 00 a4 00 01 00 a9
RX 24 bytes                 a0 14 00 b4 32 11 00 02 00 2f 00 1e 01 38 01 ff 00 f7 00 3f 01 34 01 73

TX firmware_version (0xa8)  a0 04 00 a4 a8 01 00 01
RX 10 bytes                 a0 06 00 a6 b0 03 00 a8 01 4e

TX read_otp (0xa6)          a0 04 00 a4 a6 01 00 03
RX 24 bytes                 a0 14 00 b4 a8 11 00 47 46 5f 49 54 45 5f 45 43 5f 32 30 30 36 33 00 e2

TX preset_psk_read (0xe4)   a0 04 00 a4 e4 01 00 c5
RX 10 bytes                 a0 06 00 a6 b0 03 00 e4 01 12
```

**Every checksum verifies.** Worked by hand: `0x4e`, `0xe2`, `0x73`, `0x12` — all four match. The
framing above is therefore confirmed against hardware, not merely transcribed.

### Device identity — observed

```
a8 11 00 | 47 46 5f 49 54 45 5f 45 43 5f 32 30 30 36 33 00 | e2
           G  F  _  I  T  E  _  E  C  _  2  0  0  6  3
```

`GF_ITE_EC_20063`. Upstream's 5110 reports `GF_ST411SEC_APP_12117`. This is an **ITE embedded
controller** bridging to the sensor, not the Goodix sensor MCU — and on this machine that same
controller drives the internal keyboard over i8042.

### Correction — the ACK convention (observed)

The transcribed convention above (`cmd | 0x01`) is **wrong for this device**. Acknowledgements arrive
as a distinct message with `cmd = 0xb0` and payload `[original_command][status]`:

```
b0 03 00 | a8 01 | 4e     ACK for firmware_version, status 01
b0 03 00 | e4 01 | 12     ACK for preset_psk_read,  status 01
```

`0xb0` also names `FlagTLSData` at the pack layer. Different field, different level — do not conflate.

### Correction — two transfers per command (observed)

Each command yields an ACK first, then a separate data response. The probe read once per command and
so ran one transfer behind: the firmware string arrived while it was reading for `read_otp`.
`read_otp` (`0xa6`) itself produced neither ACK nor data — either unimplemented on the EC, or still
queued. Unresolved.

The probe now reads until the data message arrives or the device goes quiet, drains the IN endpoint
before exiting, and no longer sends `read_otp`. The Run 1 transfers, regrouped by the command they
answer, are the `--replay` fixture (`run1Script` in `cmd/goodix-probe/main.go`). Verified offline only.

### Unidentified — unsolicited `0x32`

Arrived before any command could have caused it, so the EC likely emits it on attach:

```
32 11 00 | 02 00 2f 00 1e 01 38 01 ff 00 f7 00 3f 01 34 01 | 73
```

As little-endian `uint16`: `2, 47, 286, 312, 255, 247, 319, 308`. Plausibly sensor or DAC
configuration. Unknown.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
