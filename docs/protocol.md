# Goodix 51x0 wire protocol — as understood for `27c6:5120`

Working notes. Two kinds of statement appear here and they are deliberately kept apart:

- **Transcribed** — read from the upstream [goodix-fp-dump][dump] Python source (`goodix.py`,
  `protocol.py`, `driver_51x0.py`). Believed accurate for the 5110; *assumed* to hold for the 5120.
- **Observed** — measured against this machine's actual hardware (Runs 1–4 below).

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

Each opcode also carries a **payload rule**: the length the vendor driver was observed to send. The
transport refuses a payload that violates it, before a byte is written, because a payload-less `0xe4`
is what wedged the EC three times. `nop` and `check_firmware` carry no rule, because the vendor driver
never sends them and a guessed rule would read like evidence.

### `ClassSafe` — read-only, in the default allowlist

| Opcode | Name | Payload | Notes |
|---|---|---|---|
| `0x00` | `nop` | none recorded | the vendor never sends it to an ITE EC; **not** a probe step any more |
| `0xa8` | `firmware_version` | 2 (`00 00`) | **the go/no-go signal** — the one command the probe sends |
| `0xa6` | `read_otp` | 2 (`00 00`) | calibration data; the empty form got no reply in Run 1 |
| `0xae` | `get_mcu_state` | 5 (`55` + `uint32`) | answers with 20 bytes and **no ACK** |
| `0x82` | `read_register` | 5 | the vendor's only use returns the chip ID `0x2504` |

### `ClassStateChanging` — alters runtime state, no flash write; opt-in only

| Opcode | Name | Payload |
|---|---|---|
| `0x96` | `enable_chip` | 2 (`01 02`) |
| `0xa2` | `reset` | 2 (`01 14`) |
| `0x70` | `mcu_switch_to_idle_mode` | 2 (`14 00`) |
| `0x98` | `set_dac` | 8, from the OTP |
| `0x90` | `upload_config_mcu` | 224, recovered from `gfusb.dll` — see below |
| `0xd0` | `request_tls_connection` | 2 (`00 00`); no ACK |
| `0xd4` | `tls_successfully_established` | 2 (`00 00`) |
| `0x20` | `mcu_get_image` | 2 (`01 00`) |
| `0x50` | `nav_mode` | 2 (`01 00`); driver log only |
| `0x32`/`0x34`/`0x36` | `fdt_down`/`fdt_up`/`fdt_manual` | 16/14/14 — they arm the EC to emit events unprompted, so none is a read |
| `0xf4` | `check_firmware` | none recorded |
| `0xe4` | `preset_psk_read` | 8 (`03 00 02 bb 00 00 00 00`) |

`0xd2` is **not** registered. It is named in `PLAN.md`, but appears in neither the nine complete driver inits
nor either USB capture, and registering an opcode nobody has observed widens the boundary for nothing.
No sensor-register *write* is registered either: the vendor init contains none.

`0xf4` is classified conservatively: it reads state, but it appears in upstream's IAP flow, and being
wrong in that direction is cheap while being wrong in the other could cost the sensor.

`0xe4` reads the stored PSK metadata and writes nothing, and was `ClassSafe` until 2026-09-19. It moved
here because **an `0xe4` with an empty payload** wedges this device's EC (Runs 1, 2 and 4 below; Run 4
showed it needs no other command before it). The probe no longer sends it, and bisect refuses it unless
`--allow-e4` is given, in which case it goes out with the vendor's 8-byte argument. The empty frame
itself can no longer be built: the payload rule refuses it at the transport.

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

Four of the six rows this table used to hold were answered between 2026-08 and 2026-09-20; they are
kept, struck, because knowing a question *is* settled is worth as much as the answer.

| Question | Status |
|---|---|
| ~~Does the 5120 accept 51x0 framing at all?~~ | **Resolved — yes.** Every pack and message checksum verifies across both USB captures and all nine complete driver inits. The old answer here said "probe: `nop` → expect ACK `0x01`"; **do not do that** — the vendor driver never sends `nop` to an ITE EC part, and it drew no reply in Runs 2 and 3 |
| ~~Firmware version string~~ | **Resolved** — `GF_ITE_EC_20063`, via `0xa8` |
| ~~Sensor resolution~~ | **Resolved — 80 × 64**, from the driver log (chip ID `0x2504`, "ChicagoHS", sensor type 12), and independently corroborated by the TLS record length; see "How big is an image, really". Upstream `driver_51x0.py` declares 80 × **88**, which is a different part — do not assume it |
| ~~12-bit sample packing for image decode~~ | **Resolved** — transcribed from upstream `tool.py`, see below. Corroborated by the record-length arithmetic, still unverified against a real plaintext |
| PSK variant | **Open, and the wall.** The transcribed upstream key is not this device's: Windows provisioned a random PSK and sealed it (`Goodix_Cache.bin`, DPAPI). Whether the 5120 accepts the upstream key is unverified |
| What the 224-byte `0x90` config actually *does* | **Open.** The bytes are known and the entry structure is a reasonable reading, but no register in it has been identified. See "The 224-byte `0x90` config — recovered" |

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
in practice, even though it only reads. **Run 4 later confirmed it in isolation:** `0xa8` does not have to
come first, and neither does `nop`.

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

### Run 4 — 2026-09-19 22:41, `sudo ./goodix-probe --bisect --allow-e4 --steps e4 --timeout 30s` (observed)

The run [`bisect-runbook.md`](bisect-runbook.md) prescribes for settling whether `0xe4` wedges the EC
**on its own**: attach, then `0xe4` and nothing else. Run by the user with an external keyboard attached. No
usbmon capture. **Result: the internal keyboard stopped after step 1, `preset_psk_read` (`0xe4`) —
with no `nop` and no `0xa8` before it.**

```
step          TX                          RX                                        i8042 irq1  keyboard
baseline      —                           —                                         4912        alive
0 attach      —                           nothing (30 s drain)                      4955        alive
1 0xe4        a0 04 00 a4 e4 01 00 c5     ACK e4/01 after 4 ms, then nothing (30 s) 4956        DEAD
```

- **The question is closed: `0xe4` wedges the EC alone.** `0xa8` is not a precondition, and neither is
  `nop`. The frame is byte-identical to the one Run 1 and Run 2 sent: `0xe4` with an **empty payload**.
- **Same make-without-break signature as Run 2.** Between the step 0 snapshot (`irq1=4955`, 22:41:45.53)
  and the step 1 snapshot (`irq1=4956`, 22:42:47.89) the user pressed Shift exactly once — the press that
  cleared the attach check at 22:41:47.82. A press is worth 2 (make + break); only 1 arrived. `0xe4` went
  out at 22:41:47.84, about 20 ms after the make. *Interpretation:* the EC stopped serving i8042 within
  those 20 ms, before it could deliver the break. The ACPI SCI count did not move at all (330 → 330).
- **The kernel logged nothing**, as in Runs 1 and 2 — no i8042, atkbd or USB message between the `0xe4`
  and the shutdown. The probe's own `/dev/kmsg` markers stop at `step 1 preset_psk_read (0xe4): sending`;
  there is no `keyboard alive after step 1`.
- The EC answered the ACK in 4 ms and then sent nothing for the full 30 s, and the drain that followed
  got nothing either. With no usbmon capture, 60 s of silence is all that can be said; whether anything
  would have arrived later is unknown.
- Boot context: the same boot as Run 3. That boot started 18:50:32, right after the cold power cycle
  that recovered Run 2, so there was **no cold power cycle between Run 3 and Run 4** — the EC had been
  up for just under four hours. For the third consecutive time, attach produced no unsolicited `0x32`.
- Recovery: the journal shows a clean shutdown starting at 22:43:09, 26 s into the keyboard prompt —
  the user, on the external keyboard, having seen the internal one was dead. The next boot is 23:15:33,
  32 minutes later; per the user that gap is the cold power cycle. Both the keyboard and `27c6:5120`
  came back.

Consequence: the empty-payload `0xe4` has now killed the internal keyboard three times (Runs 1, 2, 4) and
is the only frame ever shown to do so. The vendor's `0xe4` **with** its 8-byte argument is answered
normally in all nine complete driver inits, so the payload — not the opcode — is what the EC cannot survive.

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
  `Windows\System32\winevt\Logs\Goodix-FingerprintProvider%4Debug.evtx`, 20 MB. The init sequence below
  comes from this log, not from USB captures.
  **Recounted 2026-09-20**, by parsing the EVTX records instead of running `strings` over them:
  **17545 records, 2026-08-15 17:29:14 to 2026-09-19 23:27:07, holding 18 inits of which 9 are
  complete.** The file is a circular 320-chunk log and has already wrapped (its header names first
  chunk 28, last chunk 27), so anything older than that span is overwritten and gone. The earlier
  reading — "2026-08-11 to 2026-09-19, 8 complete inits" — came from `strings -el`, which cannot date
  a record or tell a complete init from a short-circuited one. The record-level figures are the
  correct ones.
  **The log is itself secret-bearing (observed, 2026-09-20).** It does not only record lengths: it
  dumps received frames in full hex. The 64-byte OTP appears 18 times as `data::0xa641…` and again
  under five other labels (`Got sensor OTP::`, `got file OTP::`, `USED OTP::`, …), and the `0xe4`
  reply — a hash of the device PSK — appears 18 times as `data::0xe42a…`. The OTP's first 32 bytes
  also appear as **`sensorid:0x…`**, a label that names neither OTP nor secret and uses a single
  colon, so a search for `::` misses it entirely. Consequences: the log stays gitignored like any
  capture, **no excerpt of it may be pasted into a document, an issue or a commit message without
  being checked against those labels**, and `cmd/goodix-evtx` withholds all of them at parse time
  rather than at the print site, so there is no unredacted path through it. Host-sent `Send data::`
  frames are *not* withheld — the `0x90` config and the whole init live there, and recovering them is
  the point of the tool.
- **USBPcap captures** (`restart.pcapng`: `Restart-Service WbioSrvc`; `dump.pcapng`: 43 finger
  captures). Both show steady-state traffic only. No init runs, because the EC keeps its TLS session
  (see "Power"). Every pack and message checksum in both captures verifies. The driver doesn't zero the
  padding of its 64-byte OUT transfers (stack bytes leak into it), so ignore everything after the pack length.

Device facts, from the log: **chip ID `0x2504`**, "ChicagoHS", sensor type 12, **80 × 64 pixels**
(not upstream's 80 × 88). The OTP begins with ASCII `S2A755.`. The driver treats this as an
"ITE EC project": it sends **no `nop`** ("not to send nop for ITE EC projects") and does **no firmware
update** ("no firmware update for EC projects"). None of the 9 complete inits sends `0xe0`, `0xf0`, `0xf2`, `0xf4` or `0xf6`.

### Init sequence

Identical in all 9 complete inits. The most recent (2026-09-19 23:25:41) was re-read frame by frame
at record level on 2026-09-20 and matches this table exactly, including the reply lengths — the log
writes those as `recvd data cmd-len: 0x<cmd>-<n>`, where `n` counts the payload **plus** its checksum
byte, so `0xe4-42` is the 41-byte payload below and `0xa6-65` the 64-byte OTP.
Payloads are message payloads (checksum omitted). ACK means a `b0` message
`[cmd] 01`. The `0x90` config (224 bytes) is truncated in the log to its first 57 payload bytes, but
is **known in full** from `gfusb.dll` — see "The 224-byte `0x90` config — recovered" below.

| # | TX | payload | reply |
|---|---|---|---|
| 1 | `96` enable_chip | `01 02` | none; the driver doesn't wait for one |
| 2 | `a8` firmware_version | `00 00` | ACK, `GF_ITE_EC_20063` |
| 3 | `ae` get MCU state | `55` + `uint32` LE timestamp (ms, low bits) | **no ACK**, 20-byte state (below) |
| 4 | `e4` read production data | `03 00 02 bb 00 00 00 00` | ACK, 41 bytes: type `0xbb020003`, len `0x20`, 32-byte PSK hash (that is 40; the 41st byte is unaccounted for) |
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
**Run 4 (2026-09-19 22:41) confirmed this live and in isolation:** attach, then that one frame and nothing
else, and the keyboard died. So the empty payload is sufficient on its own. Why it is fatal is still a
hypothesis — presumably the EC's handler reads the missing argument and blocks. The same pattern fits
`read_otp`: Run 1's empty `a6` got nothing back, while the vendor's `a6 00 00` gets ACK plus 64 bytes.
Our `a8` with no payload still worked. Nothing further is to be learned from sending the empty frame
again: stay on the vendor's payloads.

The `0xe4` reply carries a hash of the device's PSK, so don't record it here.

### TLS

- Pack flag `0xb0` carries raw TLS records in both directions. After `d0`, the **EC is the TLS client**:
  it sends ClientHello, and the host (mbedTLS inside `gfusb.dll`) is the server.
- TLS 1.2, one cipher suite offered: **`0x00ae` = `TLS_PSK_WITH_AES_128_CBC_SHA256`**. PSK
  identity `Client_identity`. Corroborated 2026-09-20 from the 23:25:41 handshake in the log, whose
  ClientHello (`16 03 03 00 2f 01 00 00 2b 03 03 …`) offers exactly `00ae` and nothing else.
- The PSK is **not** the upstream zero key. It is 32 random bytes that the driver generated during
  provisioning, sealed on the host (`gf_seal_data`; the log says "read 332 bytes", and
  `C:\ProgramData\Goodix\Goodix_Cache.bin` is exactly 332 bytes, dated 2021-03-16) and written to the
  EC with `0xe0`. **The sealing is DPAPI** (observed 2026-09-20 — see "`Goodix_Cache.bin` is DPAPI"
  below), not TPM or SGX, whatever `gf_sgx_seal_data` and "IntelME pmk hash" suggest elsewhere in the
  strings. At each init the driver unseals it, hashes it and compares with the
  hash from `0xe4` ("hash equal"). A Linux driver therefore needs either that PSK, unsealed from the
  Windows side, or its own `0xe0` provisioning, which would break Windows Hello and is destructive.
  Tier 2 question; nothing to do now.
- Images arrive as a single `b0` pack of 7749 bytes holding one TLS application-data record
  (`17 03 03 1e 40`, 7744 bytes). They are only readable with the PSK.

#### How big is an image, really (hypothesis, arithmetic only, 2026-09-20)

7744 is the length of the *record*, so it is an upper bound on the plaintext and not the plaintext
itself. Suite `0x00ae` is `TLS_PSK_WITH_AES_128_CBC_SHA256` (observed in the ClientHello), which in
TLS 1.2 puts a 16-byte explicit IV in front of the ciphertext and a 32-byte MAC plus 1–16 bytes of
padding inside it:

    7744 − 16 IV      = 7728 ciphertext   (a whole number of AES blocks, as it must be)
    7728 − 32 MAC − padding(1..16) = 7680 .. 7695 bytes of plaintext

80 × 64 = 5120 samples at 12 bits, packed four samples per six bytes, is **7680 bytes exactly** — the
bottom of that range, reached with a full 16-byte padding block. Upstream's 8-byte header and 5-byte
trailer would make 7693, also inside it.

So the record length independently corroborates the 80 × 64 geometry with upstream's 12-bit packing,
which until now rested only on the chip ID and upstream's own tables. It cannot distinguish a bare
frame from one with upstream's header and trailer: both fit. Nothing here is decoded — this is
arithmetic over lengths observed on the wire, and it stays a hypothesis until a plaintext is measured.

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
sent after each finger-up — **according to the driver log only; `0x50` does not appear anywhere in
either USB capture.**

`0xae` state reply, byte 1: `0x11` = POV image valid, TLS down (the only cold init); `0x13` = both
valid; `0x02` = TLS up, no POV image. The driver skips re-init and the handshake when TLS is still up.

**Correction (2026-09-19, from the captures):** only `isTlsConnected` can be pinned to a bit. It is
bit 1 (`0x02`), which the driver logs as 1 for `0x13` and `0x02` and 0 for `0x11`. "POV image valid"
cannot be attributed: bit 0 (`0x01`) and bit 4 (`0x10`) are set together in `0x11` and `0x13` and clear
together in `0x02`, so the evidence cannot separate them, and they may be one two-bit field.
`internal/proto.DecodeMCUState` offers bit 0 under that caveat and keeps all 20 bytes raw.

### Read back from the captures (observed, 2026-09-19)

`cmd/goodix-pcap` decodes a USBPcap file offline — it imports only `internal/proto`, cannot reach a
device, and prints counts rather than payload bytes by default. Run it on `dump.pcapng` to reproduce
the following. These facts come from the wire, independently of the driver's debug log.

```
2937 USB transfers, 382 on the device (bus 2, device 2, found via its device descriptor)
382 frames decoded, 0 failed — every pack and message checksum verifies
```

| TX | count | payload length |
|---|---|---|
| `0x20` mcu_get_image | 43 | 2 |
| `0x32` fdt_down | 26 | 16 |
| `0x34` fdt_up | 43 | 14 |
| `0x36` fdt_manual | 22 | 14 |
| `0xae` get_mcu_state | 1 | 5 |

Every one of those lengths matches the vendor payloads transcribed above, which is what the opcode
payload rules in `internal/proto` are built on. 43 TLS packs, all exactly 7749 bytes of pack payload.
`0x34` was armed 43 times but produced only 21 events; `0x50` appears zero times.

Event headers actually seen, with counts:

```
0x32   02 00 3f 00  x15    02 00 2f 00  x4    02 00 3d 00  x1    02 00 37 00  x1    80 00 00 00  x5
0x34   00 02 00 00  x21
0x36   00 01 3f 00  x21    00 01 2f 00  x1
```

Arm payloads confirm the documented shape: `0c 01`/`0e 01`/`0d 01`, then six `80 xx` pairs, then a
`uint16` that only `0x32` carries and that changes between arms (a timestamp). The `0x80` before each
threshold is constant in all 91 arms.

The `0xae` reply is the same in all four captures except its last two bytes, with `isTlsConnected`
set every time:

```
02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 04 04   restart.pcapng, dump.pcapng   21:12
02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 0a 0a   disable-enable2.pcapng        23:13
02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 0e 0e   disable-enable3.pcapng        23:26
```

Bytes 0-17 are identical across all of them. Bytes 18 and 19 always carry the same value as each
other, and across these three observations that value only goes up: `04`, `0a`, `0e`. A counter of
some kind — of inits, or of power transitions — is the obvious guess, but three points in wall-clock
order are not enough to call it, and the first two are from different boots. **Hypothesis, not
observed.** They are not the TX timestamp: the host supplies that, and it differs within a session.
The debug log adds two more readings at `0e 0e` (2026-09-19 23:25:22 and 23:25:41), which bracket a
Disable, a re-enumeration and an Enable without moving — so whatever it counts, it is not USB
attachments.

### Disable device, Windows (observed twice, 2026-09-19 23:13 and 23:26)

`disable-enable2.pcapng` and `disable-enable3.pcapng` each caught a Device Manager **Disable** — the
shutdown half of the Disable/Enable that is meant to produce an init. The two are the same sequence
to the byte, differing only in the `ae` timestamp and the trailing counter of its reply:

| t | direction | frame |
|---|---|---|
| +7.6 s | TX | `96` enable_chip, payload `00 02` |
| +7.6 s | TX | `ae` get MCU state, payload `55` + timestamp |
| +7.6 s | RX | 20-byte state, `isTlsConnected` still set |
| +9.1 s / +9.8 s | — | the pending bulk IN completes with `USBD_STATUS_CANCELED`: the driver is unloading |

**The init's `96` carries `01 02`; this one carries `00 02`** — the same command with its first byte
cleared. So `enable_chip` does take a boolean, upstream's name is right, and the driver does have a
shutdown command after all. It sends no `a2` reset, no `70` idle, and does not wait for a reply to
the `96`; the `ae` that follows is the last thing it asks.

This qualifies, and does not contradict, the D0Exit finding below: idle exit sends nothing, an
explicit Disable sends `enable_chip(0)`.

**Answered 2026-09-20, from the debug log: the EC does not drop its TLS session.** After the Enable
re-enumerated the device, the `ae` at 23:25:41.273 read back
`02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 0e 0e` — byte for byte what the Disable read
19 s earlier, `isTlsConnected` still set, trailing counter still `0e`. So a Device Manager
Disable/Enable does not reset the EC's session; the driver re-handshakes because *it* lost its key
material, not because the EC did. (The counter's failure to move across this pair says little either
way: the read happens inside the init that would have bumped it.)

No USB re-enumeration appears anywhere in either capture. The only control transfers on the device
are the six of USBPcap's injected descriptor sweep at t=0, so Device Manager's Disable did not reset
or re-address the USB device.

**The Enable produces nothing *in the capture*.** `disable-enable3.pcapng` ran **84.6 s** — 74.7 s of
it after the driver unloaded — and in that time the sensor sent and received not one byte, and no new
device number appeared on the bus. Other devices on the same hub (a headset, a mouse, a disk) kept
transferring to the last second of the file, so the capture itself was alive throughout.

**Resolved 2026-09-20 by the debug log: the Enable ran a complete init, 26.6 s into that capture, and
USBPcap recorded none of it.** See "Why three Disable/Enable captures hold no init" below. The two
candidate explanations were "the Enable did not happen inside the capture window" and "USBPcap cannot
see it"; it is the second.

### The Windows partition, read offline (observed, 2026-09-20)

The Windows system partition (`/dev/nvme0n1p3`) was mounted **read-only** on Linux and three things
were taken off it: the driver debug log, the driver package, and `C:\ProgramData\Goodix\Goodix_Cache.bin`.
Nothing on the partition was written, and no Windows binary was run. All three land in gitignored
directories (`/captures/`, `/windows-driver/`) and none of them enters the repository.

One trap, recorded because it produced a false finding before it was caught: **`cp` from an `ntfs3`
mount uses `copy_file_range()`, which that driver mishandles and which silently yields a file of the
right size filled with zeros.** Eight of the nine driver-package files arrived corrupted that way, and
a zero-filled `gfusb.dll` searches clean — which briefly made the `0x90` config look as though it were
not in the DLL at all. Copy with `cat src > dst` and check `md5sum` against the source. The two
`.evtx` copies were verified byte-identical with `cmp`, so nothing drawn from the debug log is affected.

No EVTX tooling exists on this machine, so the log was read with a small record scanner rather than a
binary-XML parser: EVTX records carry their own header — magic `0x00002a2a`, size, record id and a
FILETIME — and their substitution values are stored as plain UTF-16LE, which is enough to recover
"what was logged, and when". Template-owned static text is not reconstructed, and does not need to be.

### `Goodix_Cache.bin` is DPAPI (observed, 2026-09-20)

`C:\ProgramData\Goodix\Goodix_Cache.bin`, 332 bytes, mtime **2021-03-16 19:32:15**, unchanged since —
this is the sealed PSK the TLS section describes. Its header is:

```
01 00 00 00                                       blob version 1
d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb   provider GUID
01 00 00 00                                       master-key version
<16 bytes>                                        master-key GUID
```

The provider GUID above is the well-known DPAPI constant `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`,
written in Microsoft's mixed-endian GUID layout. (The master-key GUID identifies *this* machine's key
and is not recorded.) **The blob is `CryptProtectData`
output: DPAPI, not TPM- and not SGX-sealed.** That settles how the PSK is stored.

It is user- or machine-scoped DPAPI protected by a master key, so recovering the plaintext offline
needs that master key, which is a separate question and not answered here. The rest of the blob's
bytes are deliberately **not** recorded: they are the sealed PSK. The file stays gitignored and
unpublished.

### The 224-byte `0x90` config — recovered (observed, 2026-09-20)

**The last outbound frame of the vendor init that nobody had the bytes for is now known in full.**
Extracted statically from `gfusb.dll`; the debug log alone could never have produced it.

The complete frame on the wire is **232 bytes**: pack `a0 e4 00 84`, message `90 e1 00`, the 224-byte
payload below, then the message checksum `8f`.

```
7011607100712c9d1cb918d100d100d100ba000180ca000400840015b3860000
c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000
b6980000009a000000d2000000d4000000d6000000d800000050000105d00000
00700000007200785674003412200010402a0182032200012024001400800001
005c000001560004205800030232000c02660003007c000058820080152a0108
005c008000540010016200040364001900660003007c0000582a0108005c0000
015200080054000001660003007c000058000000000000000000000000007815
```

Four independent checks, each of which would fail on a window off by one byte or one length:

- **19 occurrences in `gfusb.dll`, all byte-identical** — eighteen in `.rdata` (first at file offset
  `0xd04e2`), one in `.data` at `0x310aa0`. No variant ambiguity about which blob is the config.
- **Its first 57 bytes are exactly what the debug log shows**, in all nine complete inits over a month.
- **`sum(payload) & 0xff == 0xaa`**, the vendor's own message-checksum convention. This is what pins
  the 224-byte boundary.
- **Re-encoding it with this repository's own framing rules reproduces the logged first 64 bytes byte
  for byte**, pack checksum `0x84` included, and yields message checksum `0x8f`.

`goodix.dat`, `goodix_calib.dat` and the `SYSTEM`/`SOFTWARE` registry hives were also searched and do
**not** contain it; the config lives in the DLL.

**Structure — interpretation, not fact.** 29-byte header, then 48 four-byte entries of
`[register LE16][value LE16]`, then a 3-byte tail. It is a write **script, not a map**: registers
`0x5c`, `0x66`, `0x7c` and `0x12a` each recur three times with different values, so order is
significant and it cannot be replayed as an unordered set. Register sequence:

```
86 88 8a 8c 8e 90 92 94 96 98 9a d2 d4 d6 d8 50 d0 70 72 74 20 12a 22 24 80
5c 56 58 32 66 7c 82 12a 5c 54 62 64 66 7c 12a 5c 52 54 66 7c
```

Registers `0x0072 = 0x5678` and `0x0074 = 0x1234` put `0x12345678` across two consecutive registers —
a recognisable test or magic constant, and a useful sanity check on the entry decoding. The 29-byte
header does not fit the entry pattern and is **not** decoded.

**Consequence:** the vendor-init replay fixture can carry the real `0x90` instead of synthetic bytes,
and a USB capture of an init is no longer needed to obtain it. Such a capture is still worth having
as corroboration — see below for why none of the three attempts produced one.

### What triggers a full init (observed, 2026-09-20)

Not the MCU's TLS flag — the driver's own lifecycle state. Both of these happened within 19 s:

| time | driver state | `isTlsConnected` | what it sent |
|---|---|---|---|
| 23:25:22.459 | `DriverState:Uninstall`, "resume from S0 idle", prev state 4/5 | 1 | one `ae`, then "get pov images directly", then "Initialization done successfully" — **no config, no handshake** |
| 23:25:41.224 | `DriverState:Install`, prev state `5(D3Final)` | 1 | the complete 13-frame sequence, `96` through `d4`, including the 224-byte `0x90` and a fresh TLS handshake |

So a resume short-circuits on `isTlsConnected`, exactly as the state-byte note above says, while a
**fresh driver start runs the full init regardless of what the MCU reports** — at 23:25:41 the EC still
had its session up and the driver re-initialised anyway, because the driver had lost its own key
material. `DriverState:Install` follows a PnP start, which follows a re-enumeration.

That is the crux of the capture problem: **a full init requires a re-enumeration, and a
re-enumeration is the one thing the capture tool cannot follow.**

Also from the Disable side, at 23:25:22.396: the `96 [00 02]` quiesce write returned
`Usb write error!! status:0xc000000e` in the driver's log, yet USBPcap recorded the frame on the wire
anyway. Log and capture otherwise agree on all three Disable frames to the millisecond, which is what
makes the correlation below trustworthy.

### Why three Disable/Enable captures hold no init (observed, 2026-09-20)

**USBPcap does not follow the device across a PnP re-enumeration.** The procedure was right every
time; the capture tool missed the result. Correlating the log's 9 complete inits against the capture
windows:

| capture | window | complete init in that window |
|---|---|---|
| `disable-enable2.pcapng` | 23:13:09.726 + 22.295 s | **23:13:23.144** |
| `disable-enable3.pcapng` | 23:25:14.831 + 84.581 s | **23:25:41.462** |

Both captures contained a complete init and neither recorded one byte of it. Taking
`disable-enable3.pcapng` in detail: the sensor's last captured transfer is at 23:25:24.680, the init
begins **16.8 s later**, and neither it nor any new device address appears anywhere in the file —
while the other devices on the hub kept transferring to the last second. The device came back and the
capture never saw it.

(`disable-enable.pcapng`, attempt 2, is not in the table: it was on the wrong hub, and the nearest
complete init, 22:25:05.889, falls outside its window in any case.)

The consequence for the runbook is that **more re-enumeration is not the fix** — Uninstall plus "Scan
for hardware changes" is a stronger PnP removal and would fail the same way. See
[`docs/windows-capture-runbook.md`](windows-capture-runbook.md).

### Power

- **D0Exit (S0 idle, after 10 s idle) sends nothing to the EC.** The driver stops its read pipe and
  leaves the EC armed in FDT-down mode with its TLS session up. On D0Entry it sends only `ae` and
  re-arms `32` if needed. No shutdown or D3Final sequence appears anywhere in the log; on idle, the
  host just stops reading.
- **An explicit Device Manager Disable is different: it sends `96` `enable_chip` with `00 02`**, then
  one `ae`, then the driver unloads. See "Disable device, Windows" above. So the driver does have a
  quiesce command — the log never showed it because no init in the log was preceded by a Disable.
- So the EC tolerates the host going away, which fits Run 2: the keyboard died right after the empty
  `0xe4`, not at exit.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
