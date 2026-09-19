# Goodix 51x0 wire protocol — as understood for `27c6:5120`

Working notes. Two kinds of statement appear here and they are deliberately kept apart:

- **Transcribed** — read from the upstream [goodix-fp-dump][dump] Python source (`goodix.py`,
  `protocol.py`, `driver_51x0.py`). Believed accurate for the 5110; *assumed* to hold for the 5120.
- **Observed** — measured against this machine's actual hardware (Run 1, Run 2 below).

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
| `0xe4` | `preset_psk_read` |

`0xf4` is classified conservatively: it reads state, but it appears in upstream's IAP flow, and being
wrong in that direction is cheap while being wrong in the other could cost the sensor.

`0xe4` reads the stored PSK metadata and writes nothing, and was `ClassSafe` until 2026-09-19. It moved
here because it wedges this device's EC (Run 1, Run 2 below). The probe no longer sends it, and bisect
refuses it.

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

The first live run. It wedged the embedded controller and killed the internal keyboard; see
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

### Run 2 — 2026-09-19, `sudo ./goodix-probe --bisect` (observed)

Run by the user per [`bisect-runbook.md`](bisect-runbook.md), with an external keyboard attached. No usbmon
capture. **Result: the internal keyboard stopped after step 3, `preset_psk_read` (`0xe4`).** Baseline,
attach, `nop` and `0xa8` each passed their keyboard check.

```
step          TX                          RX                                        i8042 irq1  keyboard
baseline      —                           —                                         16458       alive
0 attach      —                           nothing (5 s drain)                       16460       alive
1 nop         a0 04 00 a4 00 01 00 a9     nothing — no ACK, no data                 16462       alive
2 0xa8        a0 04 00 a4 a8 01 00 01     ACK a8/01, then "GF_ITE_EC_20063"         16464       alive
3 0xe4        a0 04 00 a4 e4 01 00 c5     ACK e4/01, then nothing                   16465       DEAD
```

- **`0xa8` in isolation behaves as predicted:** ACK, then data, byte-identical to Run 1's regrouped
  transfers. This confirms the two-transfer and `0xb0` ACK corrections against hardware.
- **`nop` gets no reply at all**, not even the unsolicited `0x32`. So in Run 1 the `0x32` was not a
  reply to `nop`: it was probably emitted on the first attach after boot. Attaching again got nothing.
- **`0xe4` is ACKed, then the EC stops.** The ACK came back 13 ms after TX, then no data came within
  5 s, and no i8042 interrupt came after that. Run 1 ended the same way: ACK for `0xe4`, then silence,
  then a dead keyboard.
- **The EC stopped between key make and key break.** Each Shift press adds 2 to `irq1` (make + break);
  the press after step 2 added only 1. Its make scancode arrived at 18:27:52.364; `0xe4` was sent at
  52.384, before the release. The break was never delivered, so Shift stayed logically held (the user
  saw Shift stuck; the kernel logged `atkbd_event_work hogged CPU` at 18:36 and 18:47). So the EC
  stopped serving i8042 within about 100 ms of accepting `0xe4`.
- `27c6:5120` stayed enumerated, and the kernel logged nothing about i8042 or USB, as in Run 1.
- Recovery: the user rebooted at 18:47.

Interpretation (hypothesis): the EC's `0xe4` handler blocks its main loop, e.g. waiting on a sensor or
flash read that never completes, after it has queued the ACK. `0xe4` is therefore not safe on this device
in practice, even though it only reads. Not yet confirmed in isolation, and it is not known whether
`0xa8` has to come first.

Consequence (2026-09-19): `0xe4` is now `ClassStateChanging` and is no longer in the probe's steps, so the
default ceiling refuses it and `--bisect --steps e4` is rejected. Confirming it in isolation would take a
deliberate code change.

### Run 3 — 2026-09-19 20:33, `sudo ./goodix-probe --bisect` (observed)

The first live run of the probe without `0xe4` (steps `00,a8`). Run by the user after a warm reboot, not
a cold power cycle. No usbmon capture. **Result: the internal keyboard stayed alive after every step.**

```
step          TX                          RX                                        keyboard
baseline      —                           —                                         alive
0 attach      —                           nothing (5 s drain)                       alive
1 nop         a0 04 00 a4 00 01 00 a9     nothing — no ACK, no data                 alive
2 0xa8        a0 04 00 a4 a8 01 00 01     ACK a8/01 after 5 ms, then "GF_ITE_EC_20063"  alive
```

- Byte-identical to Run 2 for attach, `nop` and `0xa8`, so the replies are reproducible.
- For the second time, attach brought no unsolicited `0x32`. It has not been seen since Run 1, so it is
  not sent on every attach. Neither Run 2 nor Run 3 followed a cold power cycle, so the EC may send it only
  once per power-up. Unconfirmed.
- Attach, `nop` and `0xa8` are safe to repeat on this device. The probe as it now stands does not wedge
  the EC.

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

### Resolved — unsolicited `0x32`

Arrived before any command could have caused it:

```
32 11 00 | 02 00 2f 00 1e 01 38 01 ff 00 f7 00 3f 01 34 01 | 73
```

It is an **FDT-down event** (finger-detect, see "Vendor driver, Windows" below). It has the same format as the
`0x32` events the vendor driver receives: `02 00 <flags> 00` followed by six little-endian `uint16`
FDT samples. The Windows driver leaves the EC armed in FDT-down mode when it goes idle and never disarms it.
So after a reboot into Linux, the EC was still armed and reported a touch (or noise) as soon as someone
read the endpoint. Runs 2 and 3 saw no `0x32`, probably because nothing touched the sensor in between.

## Vendor driver, Windows (observed, 2026-09-19)

Sources:

- **Driver package** `gfusb.inf` (Goodix, DriverVer `10/27/2020,1.1.122.127`), found in the Windows
  DriverStore at `gfusb.inf_amd64_4652ced462eef64a`. The protocol lives in **`gfusb.dll`**, a UMDF driver.
  Also in the package: `EngineAdapter.dll` (WinBio engine), `AlgoChicago.dll`/`AlgoMilan.dll` (matching),
  `GoodixEventLog.dll`, and `SessionService.exe`. `SessionService.exe` is a small session-detection service,
  not the protocol driver. The PDB path names the build `Milan_Watt\MilanSpi\x64\Release_GF3658`.
- **Driver debug log.** The INF enables the ETW channel `Goodix-FingerprintProvider/Debug`, and the driver
  logs every frame it sends and receives in hex. It is at
  `Windows\System32\winevt\Logs\Goodix-FingerprintProvider%4Debug.evtx`, 20 MB, covering 2026-08-11 to
  2026-09-19, with **8 complete driver inits**. The init sequence below comes from this log, not
  from USB captures. Read offline from Linux with `strings -el`.
- **USBPcap captures** (`restart.pcapng`: `Restart-Service WbioSrvc`; `dump.pcapng`: 43 finger
  captures). Both show steady-state traffic only. No init runs, because the EC keeps its TLS session
  (see "Power"). Every pack and message checksum in both captures verifies. The driver doesn't zero the
  padding of its 64-byte OUT transfers (stack bytes leak into it), so ignore everything after the pack length.

Device facts, from the log: **chip ID `0x2504`**, "ChicagoHS", sensor type 12, **80 × 64 pixels**
(not upstream's 80 × 88). The OTP begins with ASCII `S2A755.`. The driver treats this as an
"ITE EC project": it sends **no `nop`** ("not to send nop for ITE EC projects") and does **no firmware
update** ("no firmware update for EC projects"). None of the 8 inits sends `0xe0`, `0xf0`, `0xf2`, `0xf4` or `0xf6`.

### Init sequence

Identical in all 8 inits. Payloads are message payloads (checksum omitted). ACK means a `b0` message
`[cmd] 01`. The `0x90` config (224 bytes) is truncated in the log.

| # | TX | payload | reply |
|---|---|---|---|
| 1 | `96` enable_chip | `01 02` | none; the driver doesn't wait for one |
| 2 | `a8` firmware_version | `00 00` | ACK, `GF_ITE_EC_20063` |
| 3 | `ae` get MCU state | `55` + `uint32` LE timestamp (ms, low bits) | **no ACK**, 20-byte state (below) |
| 4 | `e4` read production data | `03 00 02 bb 00 00 00 00` | ACK, 41 bytes: type `0xbb020003`, len `0x20`, 32-byte PSK hash |
| 5 | `a2` reset | `01 14` | ACK, `01 00 08` |
| 6 | `82` read register | `00 00 00 04 00` | ACK, `a2 04 25 00` (driver: chip ID `0x2504`) |
| 7 | `a6` read_otp | `00 00` | ACK, 64-byte OTP (~35 ms) |
| 8 | `a2` reset | `01 14` | ACK, `01 00 08` |
| 9 | `70` idle | `14 00` | ACK |
| 10 | `98` set DAC | `c8 0b be 00 bc 00 bc 00` (from OTP) | ACK, `01 01` |
| 11 | `90` upload config | 224 bytes | ACK, `01 01` |
| 12 | `d0` request TLS | `00 00` | no ACK; the EC starts the TLS handshake |
| 13 | `d4` TLS established | `00 00` | ACK |
| 14 | `ae` get MCU state | as above | state with `isTlsConnected=1` |
| 15 | `36`, `50`, `36`, `82 00 82 00 02 00`, `20`, `36` | calibration | — |
| 16 | `32` FDT down | armed; the driver now waits for a finger | ACK, then an event on touch |

**`0xe4` is not what wedges the EC. An `0xe4` with an empty payload is.** The vendor sends it with an 8-byte
argument (`data_type = 0xbb020003` LE, then a `uint32` length of 0) in every init and gets ACK plus data.
The probe sent `e4 01 00 c5`, which has no payload, in Run 1 and Run 2, and the EC hung after the ACK.
Hypothesis: the EC's handler reads the missing argument and blocks. The same pattern fits `read_otp`:
Run 1's empty `a6` got nothing back, while the vendor's `a6 00 00` gets ACK plus 64 bytes. Our `a8` with
no payload still worked. Not confirmed live, and not worth confirming: stay on the vendor's payloads.

The `0xe4` reply carries a hash of the device's PSK, so don't record it here.

### TLS

- Pack flag `0xb0` carries raw TLS records in both directions. After `d0`, the **EC is the TLS client**:
  it sends ClientHello, and the host (mbedTLS inside `gfusb.dll`) is the server.
- TLS 1.2, one cipher suite offered: **`0x00ae` = `TLS_PSK_WITH_AES_128_CBC_SHA256`**. PSK
  identity `Client_identity`. No certificates.
- The PSK is **not** the upstream zero key. It is 32 random bytes that the driver generated during
  provisioning, sealed on the host (`gf_seal_data`; the log says "read 332 bytes", and
  `C:\ProgramData\Goodix\Goodix_Cache.bin` is exactly 332 bytes, dated 2021-03-16) and written to the
  EC with `0xe0`. The sealing key derives from host entropy (`generate_entropy2: generate rootkey`);
  how is unknown. At each init the driver unseals it, hashes it and compares with the
  hash from `0xe4` ("hash equal"). A Linux driver therefore needs either that PSK, unsealed from the
  Windows side, or its own `0xe0` provisioning, which would break Windows Hello and is destructive.
  Tier 2 question; nothing to do now.
- Images arrive as a single `b0` pack of 7749 bytes holding one TLS application-data record
  (`17 03 03 1e 40`, 7744 bytes). They are only readable with the PSK.

### Capture loop (steady state, `dump.pcapng`)

```
TX 32 FDT down  [0c 01 + 6 × (80 xx) + uint16 timestamp]  → ACK … RX 32 event [02 00 ff 00 + 6 × u16]
TX 20 get image [01 00]                                   → ACK, RX b0 pack (TLS image)
TX 34 FDT up    [0e 01 + 6 × (80 xx)]                     → ACK … RX 34 event on lift [00 02 00 00 + 6 × u16]
   (optionally: TX 36 FDT manual [0d 01 + 6 × (80 xx)]    → ACK, RX 36 [00 01 ff 00 + 6 × u16]; TX 20 again)
```

`ff` is a flags byte (seen: `2f`, `37`, `3d`, `3e`, `3f`), probably a touched-zone mask.

The driver's own legend: FDT mode "1Down2Up3Manual" = `0x32`/`0x34`/`0x36`. The six `80 xx` pairs are
per-zone thresholds derived from the last FDT readings (hypothesis). An `0x32` event starting with
`80` (not `02`) comes back ~30 ms after an arm whose thresholds were far from the base, and the driver
re-arms at once with fresh thresholds. Hypothesis: "base invalid". `0x50` (payload `01 00`) is "nav" mode,
sent after each finger-up.

`0xae` state reply, byte 1: `0x11` = POV image valid, TLS down (the only cold init); `0x13` = both
valid; `0x02` = TLS up, no POV image. The driver skips re-init and the handshake when TLS is still up.

### Power

- **D0Exit (S0 idle, after 10 s idle) sends nothing to the EC.** The driver stops its read pipe and
  leaves the EC armed in FDT-down mode with its TLS session up. On D0Entry it sends only `ae` and
  re-arms `32` if needed. No shutdown or D3Final sequence appears anywhere in the log. The driver has
  no quiesce command; the host just stops reading.
- So the EC tolerates the host going away, which fits Run 2: the keyboard died right after the empty
  `0xe4`, not at exit.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
