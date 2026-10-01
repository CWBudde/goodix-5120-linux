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

- **The link negotiates Full Speed, 12 Mbit/s** (observed 2026-09-20), despite `bcdUSB 2.00`. With
  64-byte bulk packets that is ~1.2 MB/s at best, so a 7749-byte image pack needs at least ~6.5 ms on
  the wire and realistically more. Any imaging frame rate is bounded by this before software matters.
  Arithmetic, not measured — neither capture is on disk any more.
- **`bmAttributes 0x60` in the configuration descriptor is malformed**: bit 7 is reserved and must
  always be set. The device reports Self Powered + Remote Wakeup without it, and `lsusb` flags it
  ("Missing must-be-set bit!"). Harmless, but a plain spec violation in the descriptor.
- **Remote Wakeup is set**, consistent with the driver log's "resume from S0 idle" transitions.
- The device presents as **CDC ACM**, but the payload is not serial — the class is a wrapper around the
  bulk pair. Interface 0's interrupt endpoint `0x82` has never been observed carrying anything.
- No kernel driver bound to either interface — no `/dev/ttyACM*`, and the `driver` symlinks under
  `/sys/bus/usb/devices/1-4:1.{0,1}/` do not resolve. That is this machine; `cdc_acm` binding is a
  plausible outcome elsewhere, which is why `internal/transport` enables libusb auto-detach.
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

PSK provenance varies across the family — sealed (hardware-specific), white-box, or all-zero. This 5120
uses a **sealed, hardware-specific** key: Windows provisioned a random 32-byte PSK and sealed it with
DPAPI in `Goodix_Cache.bin`. It has been recovered offline; see
[`dpapi-runbook.md`](dpapi-runbook.md).

**Confirmed offline (2026-09-20).** The suite the family uses, `PSK-AES128-CBC-SHA256` (`0x00ae`,
`TLS_PSK_WITH_AES_128_CBC_SHA256`), is offered by this machine's openssl (3.5.5) and negotiates at the
default security level with exactly the `s_server` line above — no `@SECLEVEL=0` needed here.
`internal/tlspsk` drives that subprocess as the **server** (the device is the client); `Config.Cipher`
is an optional override for distributions that drop legacy CBC PSK suites, and `TestNegotiatesDeviceSuite`
pins the negotiation. The recovered device PSK reaches `Config.PSK` through `tlspsk.LoadPSK` (raw key file)
or `tlspsk.ParsePSKHex`. What stays unverified is only what a live handshake settles: whether the EC
accepts that PSK, and the exact record framing over `d0`.

### The bridge (our side, 2026-09-20)

`internal/session` is the plumbing between the two. It is **half duplex on purpose**: read from the
device, forward to the local endpoint, read whatever that has to say, forward it back, in turns. That
matches how a handshake proceeds — each side speaks in flights — and it means nothing writes to the USB
OUT endpoint while something else is reading from it.

Records travel to the device through `transport.SendTLS`, which wraps them in a `0xb0` pack. That is a
write path with **no opcode**, so the class ceiling has nothing to classify; the gate instead requires
`Options.AllowTLSData` (off by default, set only by `--tls`) and refuses anything that is not a whole
number of TLS records. Half a record is the same shape of mistake as an `0xe4` with its argument missing.

**How success is detected:** the local endpoint's ChangeCipherSpec followed by its Finished. In TLS 1.2 a
server sends those only after verifying the client's Finished, which it can only do if both ends derived
the same keys — so reaching that point *is* the answer to "does the EC accept our PSK". A rejection
arrives as a plaintext alert, whose description is readable: `bad_record_mac`, `decrypt_error`,
`handshake_failure` and `unknown_psk_identity` are reported as `session.ErrPSKMismatch`, anything else as
a plain alert. That classification is an INTERPRETATION — no alert ever says "wrong PSK".

Rehearsed offline against `session.LoopbackEC`, an `openssl s_client` dressed in Goodix framing: it is the
TLS client, it offers only `0x00ae` over TLS 1.2, it wraps its records in `b0` packs, and — like the EC —
it says nothing at all until `0xd0` arrives. Both outcomes are covered, and the rejection really does come
back as `bad_record_mac`. What that proves is our framing and sequencing against a real TLS
implementation; it proves nothing about the EC, whose timing, pack sizes and choice of key are its own.

## Open questions

Four of the six rows this table used to hold were answered between 2026-08 and 2026-09-20; they are
kept, struck, because knowing a question *is* settled is worth as much as the answer.

| Question | Status |
|---|---|
| ~~Does the 5120 accept 51x0 framing at all?~~ | **Resolved — yes.** Every pack and message checksum verifies across both USB captures and all nine complete driver inits. The old answer here said "probe: `nop` → expect ACK `0x01`"; **do not do that** — the vendor driver never sends `nop` to an ITE EC part, and it drew no reply in Runs 2 and 3 |
| ~~Firmware version string~~ | **Resolved** — `GF_ITE_EC_20063`, via `0xa8` |
| ~~Sensor resolution~~ | **Resolved — 64 columns × 80 rows.** 5120 samples from the driver log (chip ID `0x2504`, "ChicagoHS", sensor type 12), and independently corroborated by the TLS record length; see "How big is an image, really". The orientation is measured, from the first real frame (Run 20) Upstream `driver_51x0.py` declares 80 × **88**, which is a different part — do not assume it |
| ~~12-bit sample packing for image decode~~ | **Resolved** — transcribed from upstream `tool.py`, see below. Corroborated by the record-length arithmetic, still unverified against a real plaintext |
| PSK variant | **The device key is recovered; acceptance is still the wall.** The upstream zero key is not this device's — Windows sealed a random PSK (`Goodix_Cache.bin`, DPAPI), now unsealed offline (see `dpapi-runbook.md`) and wired into `internal/tlspsk`. Run 11 reached a live handshake but stalled **before** any key material was used, so this remains untested |
| What the 224-byte `0x90` config actually *does* | **Open**, but it is *accepted*: Run 11 sent it live and the EC answered `01 01`. The bytes are known and the entry structure is a reasonable reading; no register in it has been identified. See "The 224-byte `0x90` config — recovered" |
| ~~How the EC wants a server flight framed~~ | **Resolved — one pack per record**, from the driver log of a completed handshake (see "The vendor's handshake, read from the driver log"). That is Run 11's framing, so the framing did not cause Run 11's stall; Run 17 found the cause in the bridge's read timing. The bridge sends one pack per record; `--tls-coalesce-flight` keeps the other |

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

`internal/image.Decode12BitRaw` implements this exact layout, guarded by a pack→unpack round-trip test
(`image_test.go`). For **this** part at 64 × 80 the payload is 5120 samples = **7680 bytes exactly**
(`5120 / 4 * 6`); the decoder is verified in code but still unconfirmed against a real 5120 plaintext,
which the live capture in Phase 5c will settle. See "How big is an image, really".

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

### Run 5 — 2026-09-20 12:41, `sudo ./goodix-probe --bisect` (observed)

Phase 4 step 1: the first live run since the payload rules landed and `nop` was dropped, so the default
bisect is now attach + `0xa8` only (steps `a8`). Run by the user with an external keyboard attached. No
usbmon capture. **Result: the internal keyboard stayed alive after every step.**

```
step          TX                                 RX                                        i8042 irq1  ec refr  keyboard
baseline      —                                  —                                         4838        0        alive
0 attach      —                                  nothing (5 s drain)                       4841        4        alive
1 0xa8        a0 06 00 a6 a8 03 00 00 00 ff      ACK a8/01, then "GF_ITE_EC_20063"         4843        7        alive
```

- **`0xa8` now carries its vendor payload `00 00`.** The frame is `a0 06 00 a6 | a8 03 00 00 00 ff`, not
  the empty `a0 04 00 a4 a8 01 00 01` of Runs 2–3; the reply is identical (`GF_ITE_EC_20063`), confirming
  the EC accepts the longer, vendor-correct form.
- For the fourth consecutive time, attach brought **no unsolicited `0x32`** (5 s drain, 0 transfers). Run 5
  followed a warm session, not a cold power cycle, so this stays consistent with the "once per power-up"
  reading from Run 3 without settling it.
- **The EC refresh counter advanced 0 → 4 → 7** across the run — the health signal that replaced the SCI
  count. The i8042 count rose 4838 → 4841 → 4843, in step with the three Shift presses. Both moving is the
  healthy baseline for the runs to come.
- Attach and the vendor `0xa8` are safe on this device. Phase 4 step 1 passed; step 2 adds `0xae`.

### Run 6 — 2026-09-20 12:43, `sudo ./goodix-probe --bisect --steps a8,ae` (observed)

Phase 4 step 2: attach, `0xa8`, then the first live `0xae` (`get_mcu_state`) with the vendor payload
`55 a2 52 00 00`. Run by the user with an external keyboard attached. No usbmon capture. **Result: the
internal keyboard stayed alive after every step.**

```
step          TX                                    RX                                              keyboard
baseline      —                                     —                                              alive
0 attach      —                                     nothing (5 s drain)                            alive
1 0xa8        a0 06 00 a6 a8 03 00 00 00 ff         ACK a8/01, then "GF_ITE_EC_20063"              alive
2 0xae        a0 09 00 a9 ae 06 00 55 a2 52 00 00…  no ACK, 20-byte state (below)                  alive
```

Counters: i8042 `irq1` 4881 → 4887, EC refreshes 0 → 15, sensor enumerated throughout.

The `0xae` reply, decoded by `proto.DecodeMCUState`:

```
02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 10 10
^^ Version 0x02
   ^^ Status 0x02  -> TLSConnected = true, POVImageValid = false
                                             ^^^^^ trailing counter (captures showed 04 04)
```

- **`0xae` answers directly, with no ACK** — the first live confirmation of the receive-without-ACK path
  the code already handled for this opcode.
- **`Status = 0x02` means TLS is still up in the EC**, carried over from a prior Windows session across the
  reboot into Linux. This is the same `isTlsConnected` short-circuit the vendor driver relies on: the EC
  retains its TLS session across power/OS cycles. We do not hold the session keys, so the flag is an
  observation, not something we can ride — but it confirms the EC's TLS state is persistent, which bears
  on Phase 5.
- **Bytes 0–17 are byte-identical to the steady-state reply in both Windows captures** (`dump.pcapng`,
  `restart.pcapng`); only the trailing 2-byte counter differs (`10 10` here vs `04 04` there), exactly the
  one field `docs/protocol.md` predicted would vary.

Phase 4 steps 1 and 2 have now both passed live. `0xae` is safe on this device.

### Run 7 — 2026-09-20 12:46, `sudo ./goodix-probe --bisect --steps a8,ae` (observed)

The confirmation run the plan requires before `0xe4`: steps 1–2 a second time. **Byte-identical to Run 6**
— `GF_ITE_EC_20063`, then the `0xae` state `02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 10 10`
(`Status = 0x02`, TLS still up, trailing counter unchanged at `10 10`), no ACK, i8042 4897 → 4903, EC
refreshes 0 → 11, keyboard alive after every step. The `0xa8`/`0xae` exchanges are reproducible on this
device. Steps 1 and 2 have each now passed twice, meeting the gate on Phase 4 step 3 (`0xe4`).

### Run 8 — 2026-09-20 12:48, `sudo ./goodix-probe --bisect --allow-e4 --steps a8,ae,e4` (observed)

**Phase 4 step 3 — the wedge hypothesis, tested and confirmed the safe way.** Attach, `0xa8`, `0xae`,
then `0xe4` (`preset_psk_read`) **with its 8-byte vendor payload** `03 00 02 bb 00 00 00 00`. Run by the
user with an external keyboard attached. No usbmon capture. **Result: the internal keyboard stayed alive
after every step, and `0xe4` returned an ACK followed by a 41-byte data reply.**

```
step          TX                                         RX                                   keyboard
baseline      —                                          —                                    alive
0 attach      —                                          nothing (5 s drain)                  alive
1 0xa8        a0 06 00 a6 a8 03 00 00 00 ff              ACK a8/01, "GF_ITE_EC_20063"         alive
2 0xae        a0 09 00 a9 ae 06 00 55 a2 52 00 00 …      no ACK, 20-byte state (as Run 6/7)   alive
3 0xe4        a0 0c 00 ac e4 09 00 03 00 02 bb 00 00…    ACK e4/01, then 41-byte reply        ALIVE
```

Counters: i8042 `irq1` 4909 → 4917, EC refreshes advancing, sensor enumerated throughout.

- **This settles the question the empty-frame runs could not.** The empty-payload `0xe4` wedged the EC in
  Runs 1, 2 and 4; the vendor's `0xe4` **with** its argument is answered normally and leaves the keyboard
  working — exactly as the driver's own nine complete inits do. **The payload, not the opcode, is fatal.**
  The transport already refuses the empty form (`TestSendRefusesTheFrameThatWedgedTheEC`); this is the
  live confirmation that the vendor form is safe.
- The `0xe4` reply, framing only:

  ```
  e4 2a 00 | 00 03 00 01 bb 20 00 00 00 | <32 bytes WITHHELD> | <checksum>
             ^^^^^^^^^^^^^^ data-type header, then 0x20 = 32-byte length
  ```

  The 32-byte field is **a hash of the device PSK** and is deliberately **not reproduced here or anywhere
  in the repo**, per `CLAUDE.md` and `PLAN.md`. It is `cmd/goodix-pcap`'s and `internal/evtx`'s reason for
  refusing the `0xe4` body, and the same rule applies to a live run: the bytes were seen on the operator's
  screen and go no further. What is safe to state is that the reply is well-formed, 41 bytes of message,
  and declares a 32-byte payload — matching the length the vendor log records (`recvd data cmd-len:
  0xe4-42`) without its bytes.
- **Phase 4 steps 1–3 are complete.** The plaintext half of the vendor init — `0xa8`, `0xae`, `0xe4` —
  now runs live on this hardware with no ill effect. Step 4 (`a2`, `82`, `a6`) is next; `d0` and beyond
  stay gated on the PSK (Phase 5).

### Run 9 — 2026-09-20 12:53, `sudo ./goodix-probe --bisect --steps a8,ae,82` (observed)

Phase 4 step 4, first half: attach, `0xa8`, `0xae`, then `0x82` (`read_register`) with the vendor payload
`00 00 00 04 00` — the read the vendor uses for the chip ID. Run by the user with an external keyboard
attached. No usbmon capture. **Result: the internal keyboard stayed alive after every step; `0x82`
returned an ACK and a 4-byte register value, but not the chip ID the vendor read returns.**

```
step          TX                                       RX (data)              keyboard
1 0xa8        a0 06 00 a6 a8 03 00 00 00 ff            "GF_ITE_EC_20063"      alive
2 0xae        a0 09 00 a9 ae 06 00 55 a2 52 00 00 …    02 02 31 … 10 10       alive
3 0x82        a0 09 00 a9 82 06 00 00 00 00 04 00 1e   01 00 80 1b            alive
```

- **`0x82` is safe** on this device: ACK `82/01`, then a 4-byte payload, keyboard alive, counters ticking
  (i8042 5745 → 5753, EC refreshes 0 → 9).
- **The value is `01 00 80 1b`, not the vendor's `a2 04 25 00`.** In the vendor init the same read returns
  `a2 04 25 00`, whose bytes 1–2 (`04 25` LE) are the chip ID `0x2504` (`docs/protocol.md`, init step 6).
  Here bytes 1–2 (`00 80`) are `0x8000` — the register does not hold the chip ID.
- **The difference is the `a2` reset.** In the vendor sequence `a2` (`reset`) runs immediately before
  `0x82`; this run skipped it, because `a2` is `ClassStateChanging` and cannot go through `--steps`. So the
  chip-ID register is populated by the reset, not standing in the sensor at rest. This answers the open
  question from Phase 4 step 4: **reading the chip ID live requires the preceding `a2` reset**, which in
  turn requires a deliberate `--allow-a2` path added the way `--allow-e4` was. Until then, `0x82` is
  confirmed safe but reads a pre-reset value, not `0x2504`.
- The `0xa8` and `0xae` replies were identical to Runs 6–8 (`0xae` still `Status = 0x02`, TLS up).

### Run 10 — 2026-09-20 13:08, `sudo ./goodix-probe --bisect --allow-a2 --steps a8,ae,a2,82,a6` (observed)

Phase 4 step 4, complete: attach, `0xa8`, `0xae`, then the reset `0xa2` (admitted by the new
`--allow-a2`), the chip-ID read `0x82`, and the OTP read `0xa6`. Run by the user with an external keyboard
attached. No usbmon capture. **Result: the internal keyboard stayed alive after every step, and with the
reset ahead of it the chip-ID read returned `0x2504` — the value Run 9 could not get without the reset.**

```
step          TX                                       RX (data)            keyboard
1 0xa8        a8 03 00 00 00 …                         "GF_ITE_EC_20063"    alive
2 0xae        ae 06 00 55 a2 52 00 00 …                02 02 31 … 10 10     alive
3 0xa2 reset  a2 03 00 01 14 …                         ACK + 01 00 08       alive
4 0x82        82 06 00 00 00 00 04 00 …                a2 04 25 00          alive
5 0xa6 OTP    a6 03 00 00 00 …                         S2A755. + [WITHHELD] alive
```

Counters: i8042 `irq1` 6429 → 6442, EC refreshes 0 → 30, sensor enumerated throughout.

- **`0xa2` reset is safe on this device.** ACK `a2/01`, then a 3-byte data reply `01 00 08` — byte-identical
  to the vendor log's reset reply (`docs/protocol.md`, init step 5). Keyboard alive.
- **`0x82` now reads the chip ID `0x2504`.** The reply data is `a2 04 25 00`; bytes 1–2 (`04 25` LE) are
  `0x2504`, exactly the vendor value. Run 9 read `01 00 80 1b` from the same command **without** the reset;
  this run adds the reset and gets `0x2504`, confirming live that **the chip-ID register is populated by
  the `a2` reset**. The sensor part is now identified from the device itself, not only the driver log —
  which independently backs the 5120-sample geometry (see "How big is an image, really").
- **`0xa6` returned a 64-byte OTP.** It begins with the ASCII prefix `53 32 41 37 35 35 2e` = **"S2A755."**,
  matching the `sensorid` prefix already documented from the Windows log. **The rest of the OTP — the
  `sensorid` proper — is deliberately not reproduced here or anywhere in the repo**, the same rule applied
  to the `0xe4` PSK hash: the bytes were seen on the operator's screen and go no further. What is safe to
  state is that the reply is well-formed, 64 bytes, and its public prefix matches the log, so the live OTP
  and the captured OTP are the same device.
- The reset ran between `0xae` (which reported TLS still up) and the later reads; whether it dropped the
  EC's TLS session was not re-checked (no second `0xae` after it). It can be measured later if it matters.

**Phase 4 is complete through its planned plaintext extent** (steps 1–4, Runs 5–10). Every safe frame of
the vendor init — `a8`, `ae`, `e4`, `a2`, `82`, `a6` — now runs live on this hardware with no ill effect.
Step 5 stops here by design: `70`/`98`/`90` configure the sensor and `d0` starts the TLS handshake, which
cannot complete without the PSK (Phase 5).

### Run 11 — 2026-09-20 15:58, `sudo ./goodix-probe --bisect --tls --psk … --steps 96,a8,ae,a2,82,a6,a2,70,98,90` (observed)

Phase 5a in one run plus the first attempt at 5b. Flags `--allow-96 --allow-a2 --allow-70 --allow-98
--allow-90 --allow-d0 --allow-d4`. Run by the user with an external keyboard attached. No usbmon capture.
**Result: the whole vendor init ran live with the keyboard alive after every one of the ten steps, the EC
opened a TLS handshake on `0xd0` — and the handshake then stalled after the server's first flight.**

```
step             TX                                 RX (data)              keyboard
1  0x96 enable   96 03 00 01 02 …                   nothing (no ACK)       alive
2  0xa8          a8 03 00 00 00 …                   "GF_ITE_EC_20063"      alive
3  0xae          ae 06 00 55 a2 52 00 00 …          02 02 31 … 12 12       alive
4  0xa2 reset    a2 03 00 01 14 …                   ACK + 01 00 08         alive
5  0x82          82 06 00 00 00 00 04 00 …          a2 04 25 00            alive
6  0xa6 OTP      a6 03 00 00 00 …                   S2A755. + [WITHHELD]   alive
7  0xa2 reset    a2 03 00 01 14 …                   ACK + 01 00 08         alive
8  0x70 idle     70 03 00 14 00 …                   ACK only, then quiet   alive
9  0x98 set_dac  98 09 00 [WITHHELD OTP-derived]    ACK + 01 01            alive
10 0x90 config   90 e1 00 … (224 bytes)             ACK + 01 01            alive
   0xd0 TLS      d0 03 00 00 00 …                   a ClientHello          alive
```

Counters: i8042 `irq1` 15545 → 15571, EC refreshes 0 → 69, sensor enumerated throughout.

**New, and all of it live:**

- **`0x96` gets no ACK and no data at all**, as the vendor log implies. Five seconds of silence, keyboard
  fine. It is the one init frame that is write-only.
- **`0x70`, `0x98` and `0x90` are all safe on this device.** `0x70` answers with an ACK and then nothing;
  `0x98` and `0x90` answer `01 01`, byte-identical to the vendor log. The 224-byte `0x90` config recovered
  from the Windows driver is therefore **accepted by the EC** — the largest single state change in the init,
  and it went in without complaint.
- **`0xae` now reports `… 12 12` where Run 10 saw `10 10`.** Same frame, different state; the two bytes
  move with where the init has got to.
- **`0xd0` makes the EC open a TLS 1.2 handshake as the client, in a `0xb0` pack**, exactly as the Tier-2
  transcription said. This was previously unverified on hardware. The pack and the record:

  ```
  b0 34 00 e4 | 16 03 03 00 2f | 01 00 00 2b 03 03 <32-byte random>
                                 00 | 00 04 00ae 00ff | 01 00
  ```

  A 52-byte record in a 56-byte pack. Decoded: ClientHello, TLS 1.2, **empty session id**, exactly two
  cipher suites — **`0x00ae` = `TLS_PSK_WITH_AES_128_CBC_SHA256`** and `0x00ff`, the renegotiation SCSV —
  one compression method (null), and **no extensions field at all**: not an empty one, absent. The 43-byte
  handshake body is fully accounted for without it. So `0x00ae` is now confirmed **from the device**, not
  only from the driver log, and the EC's TLS stack is a minimal one.

**Where it stopped.** The host (openssl `s_server`) answered with an 81-byte ServerHello and a 4-byte
ServerHelloDone, which the bridge sent as **two separate `0xb0` packs**. The EC replied with a single
zero-length transfer and then said nothing for the whole 20-second handshake timeout. No alert, in either
direction. Final counts: 1 record to the host, 2 to the device. Keyboard alive afterwards.

The server flight was reproduced offline afterwards by replaying the EC's ClientHello above at the same
openssl build, which returns:

```
16 03 03 00 51  ServerHello      77 bytes: TLS 1.2, 32-byte random, 32-byte session id,
                                 cipher 00ae, compression 0, extensions: ff01 renegotiation_info
16 03 03 00 04  ServerHelloDone   0 bytes
```

95 bytes, and openssl writes **both records in one socket write** — the split into two packs was the
bridge's, not the server's.

**What the silence means.** A stack that cannot parse a flight sends an alert; this one sent nothing, which
looks more like an endpoint still waiting for the rest of a flight it reads one transfer at a time. That is
now the leading explanation, so the bridge sends a flight as one pack (`session.Bridge.PumpHost`), with
`--tls-record-per-pack` to restore this run's framing for comparison. **Unconfirmed** — and the vendor
capture cannot settle it, because `dump.pcapng` is steady-state and contains 43 device→host TLS packs and
**no host→device TLS pack at all**.

*Superseded 2026-09-30:* the driver log shows the vendor sending one pack per record, like this run, and a
server flight with the same contents. This run's init left out `0xe4`, which the vendor never does. See
"The vendor's handshake, read from the driver log".

If one pack per flight does not fix it, the remaining suspects are the flight's *contents*: the 32-byte
session id and the `renegotiation_info` extension that the EC's own hello never asked for, and the absence
of a ServerKeyExchange (openssl omits it with no PSK identity hint; RFC 4279 §2 permits either). Both are
openssl's to change, and **a record cannot be rewritten in passing** — the Finished MACs cover the
transcript, so editing a byte in the middle breaks the handshake it would be trying to fix.

**The PSK is still untested.** The EC never sent a ClientKeyExchange, so no key material was ever used on
either side. Phase 5b's question is still open, and this run says nothing either way about whether the
recovered key is right.

### Run 12 — 2026-09-20 16:17, the same command as Run 11, **16 minutes later and without a power cycle** (observed)

**Result: the keyboard was lost at step 8, and the EC had been answering almost nothing since step 2.** This
run never reached the TLS bridge. Recovered with a cold power cycle.

```
step             TX                                 RX                       keyboard
1  0x96 enable   96 03 00 01 02 …                   nothing (expected)       alive
2  0xa8          a8 03 00 00 00 …                   NOTHING — no ACK         alive
3  0xae          ae 06 00 55 a2 52 00 00 …          02 08 31 … 14 14         alive
4  0xa2 reset    a2 03 00 01 14 …                   NOTHING — no ACK         alive
5  0x82          82 06 00 00 00 00 04 00 …          NOTHING — no ACK         alive
6  0xa6 OTP      a6 03 00 00 00 …                   NOTHING — no ACK         alive
7  0xa2 reset    a2 03 00 01 14 …                   NOTHING — no ACK         alive
8  0x70 idle     70 03 00 14 00 …                   NOTHING — no ACK         DEAD
```

Counters: i8042 `irq1` 15816 → 15839, then **frozen at 15839** across the whole 30 s wait while EC refreshes
kept climbing 81 → 87. So this is a real wedge, not a missed key press.

**The EC was already in a bad state when the run started**, and the state it was in is Run 11's. The two runs
are the same boot — `irq1` carries on from 15571 to 15816 — and nothing power-cycled in between. What
changed since Run 11:

- **`0xa8` answered nothing.** Fifteen minutes earlier the same frame returned `GF_ITE_EC_20063`. Same for
  `0xa2`, `0x82`, `0xa6` and `0x70`, all of which had answered in Run 11.
- **`0xae` still answered** — and it is the *only* command that did. Its reply changed: `02 08 31 … 14 14`
  against Run 11's `02 02 31 … 12 12` before `0xd0`. Byte 1 and the last two bytes move with the EC's state,
  and byte 1 going `02` → `08` is the difference between "no TLS" and "a TLS handshake is open".

**The finding, and it is a procedural one: an unfinished TLS handshake leaves the EC unable to answer
plaintext commands, and it does not recover on its own.** Run 11 left the EC waiting inside a handshake. In
that state it takes a plaintext frame, acknowledges nothing, and the only window left is `0xae`. Sending the
whole init into it wedged the i8042 bridge and the keyboard with it.

So **a cold power cycle is mandatory after any `--tls` run that does not complete**, and this is now enforced
rather than remembered: after attach, a bisect run sends `0xa8` as a health check and refuses to send a
single step if nothing comes back (`checkECResponsive` in `cmd/goodix-probe/bisect.go`). `0xae` is
deliberately *not* the probe — it is the one command a stuck EC still answers, so it cannot tell the two
states apart. This run would have stopped at the health check with the keyboard alive.

**Still unknown:** whether a plaintext command can bring the EC out of the TLS state at all. `0xa2` (reset)
did not, which is the obvious candidate and the interesting negative result here. Whether `0xd0` can be
re-sent to restart a handshake, or whether the EC will only ever want one per power cycle, is untested.

### Run 13 — 2026-09-20 16:37, the same command again (observed)

**Stopped by the new health check after attach, having sent nothing but the `0xa8` probe itself.** The
baseline keyboard check passed, `0xa8` drew no reply, and the run refused to send the first step. Exit 1, no
wedge.

Two things worth keeping:

- **The internal keyboard recovered without a reboot, and the EC did not.** `irq1` continues *upward* from
  Run 12 — 15839 at the wedge, 16660 at this baseline — so this is the same boot, with no cold power cycle
  in between, and the keyboard has been generating interrupts again. The host's i8042 came back on its own;
  the EC stayed deaf. **So a live keyboard says nothing about the EC's state**, which is exactly why the
  health check is a separate probe rather than an inference from the keyboard check.
- **The stuck state survives everything short of removing power.** By this point it had survived a reset
  (`0xa2`, twice in Run 12), a close and re-attach of the USB interface, and 36 minutes.

### Run 14 — 2026-09-20 19:17, the same command, on a fresh boot (observed)

**Stopped by the health check again: `0xa8` drew nothing, no step was sent, keyboard alive.** `irq1=1193`
at baseline, so this is a new boot. The journal shows the previous boot ending 18:12:52 and this one
starting 19:02:38, a 50-minute gap that fits a cold power cycle. So whatever was done in that gap did not
bring the EC back. The run sent only `0xa8`, so there is no `0xae` reply to say what state the EC was in.

### Run 15 — 2026-09-30 02:39, `sudo ./goodix-probe --bisect --read-state` (observed)

The first `--read-state` run, ten days and at least three boots after Run 14. **The EC is still in Run 12's
state. Keyboard alive at every check.** Nothing was sent after the `0xae`.

```
step            TX                         RX                                                keyboard
0 attach        —                          nothing (5 s drain)                               alive
health  0xa8    a8 03 00 00 00 …           nothing                                           —
read    0xae    ae 06 00 55 a2 52 00 00 …  02 08 31 03 00 00 01 00 90 63 00…00 19 19 (no ACK)  alive
```

Counters: i8042 `irq1` 72217 → 72226, EC refreshes 0 → 13, sensor enumerated throughout.

- **Status is still `0x08`** with the TLS bit clear. That is the reply Run 12 got, so the handshake
  Run 11 left open has survived every reboot since 2026-09-20, including the cold power cycle before Run 14.
- **The counter rose from `0x14` to `0x19`.** It kept counting instead of restarting at `0x02`, so the
  EC's RAM has not been cleared since Run 12. What increments it is still unknown: Runs 6–10 left it at
  `10`, so it is not one step per `0xae`.
- **Byte 3 is `03`**, where Runs 6–12 saw `00`. The Windows driver log's replies also have `03` there
  (`0x020231030000…`). Its meaning is unknown.
- `0xae` into the stuck EC is safe twice now (Run 12, Run 15). `--read-state` did what it was built for.

### Run 16 — 2026-09-30 03:10, `sudo ./goodix-probe --bisect --read-state`, after an EC reset (observed)

**The EC is back. `0xa8` answered the health check, the default step ran, and the keyboard was alive at every
check.** Before this run, the user shut down with the **charger plugged in** and held the power button for
**40 s** (variant 1 below). The journal shows the shutdown at 02:54:54 and the boot at 03:01:50. `irq1=219` at
baseline.

```
step            TX                    RX                                          keyboard
0 attach        —                     nothing (5 s drain)                         alive
health  0xa8    a8 03 00 00 00 …      ACK a8/01, then "GF_ITE_EC_20063"           —
1 0xa8          a8 03 00 00 00 …      ACK a8/01, then "GF_ITE_EC_20063"           alive
```

- **The same stuck state as Run 15, 30 minutes earlier and one boot before**, is gone. Between the two runs,
  the only thing done to the machine was the shutdown and the 40 s hold with the charger connected. So that
  procedure resets the EC, and the older one (charger unplugged, ~30 s) did not in Run 14. **One
  observation each**, so this is what worked, not a proven rule. The ASUS-style explanation fits: the reset
  needs the adapter present, the hold time or both.
- `--read-state` sent no `0xae` because the health check passed, so this run has no counter reading. The
  next run that sends `0xae` should show whether the counter restarted at `0x02` the way the one Windows-log
  cold init did.
- The health check logged the version string as "unsolicited", because it stopped reading at the ACK. It
  now reads the data transfer too. The test for that found a real flaw: the check passed on **any**
  transfer, so an unsolicited `0x32` finger-detect event would have let a stuck EC through. It now passes
  only on the ACK or data for `0xa8` (`TestHealthCheckIgnoresUnsolicitedEvents`).

### Run 17 — 2026-09-30 03:41, `sudo ./goodix-probe --bisect --tls --psk … --allow-e4 … --steps 96,a8,ae,e4,a2,82,a6,a2,70,98,90` (observed)

The vendor's full init, `0xe4` included, then the bridge with one pack per record. Run by the user with an
external keyboard attached, after Run 16's EC reset. **Result: every step answered exactly as in the
vendor log, the keyboard stayed alive throughout, and the handshake got one message further than Run 11
before stalling — on our side.**

- **The EC was fresh:** `0xae` answered `02 00 31 03 00 00 01 00 00 63 00 … 02 02`. The counter is back
  at `02 02`, the value of the one EC reset in the Windows log, so Run 16's hold really reset the EC. Byte 1
  is `0x00` (TLS down) where the vendor's cold init saw `0x11`.
- **`0xe4` answered ACK + 41 bytes** (the PSK hash; withheld). **`0x82` returned `a2 04 25 00`**, the chip ID
  `0x2504`, now that the `a2` reset precedes it as in the vendor order.
- **TLS:** ClientHello (47-byte body, same shape as Run 11) → ServerHello (81) and ServerHelloDone (4) as two
  packs → **the EC answered with its ClientKeyExchange**, identity `Client_identity`, 4 ms later: the
  vendor's exact message, and further than Run 11 ever got. Then a zero-length transfer 256 ms later, and
  nothing for the rest of the 20 s. No alert.

**Why it stalled: the bridge stopped reading the EC.** After forwarding the ClientKeyExchange, the bridge
turned to openssl and waited out `DefaultHostIdle` (250 ms) for a reply that could not come — openssl
needs the EC's ChangeCipherSpec and Finished first — and read nothing from the device meanwhile. The
vendor's EC sends those two records 22 ms and 27 ms after its ClientKeyExchange, and the vendor driver
keeps a read pending at all times ("start readpipe!!!"). The first read after the blind window returned
a zero-length transfer, 256 ms after the ClientKeyExchange.

**Run 11 was the same fault**, one message earlier: the bridge sent ServerHelloDone and then waited out
HostIdle for more host records, exactly when the vendor's EC sends its ClientKeyExchange (1 ms later),
and the zero-length transfer came 256 ms after ServerHelloDone. Run 17 got the ClientKeyExchange only
because the default path now sends the flight *after* gathering it and reads the device straight after.
**So the `0xe4` explanation written earlier today is not supported:** the missing `0xe4` may or may not
have mattered, and the blind window explains both stalls on its own. `0xe4` stays in the init because
the vendor sends it.

**Hypothesis, not observed:** the EC does not hold a record in its IN endpoint indefinitely; when the
host does not read it within some bound below 250 ms, the EC gives up on it (the zero-length transfer)
and its TLS stack stalls, having "sent" a record the host never received.

**Fixed in the bridge:** it keeps reading the device while the EC is mid-flight (after a
ClientKeyExchange, until its Finished), and ends the server's first flight at ServerHelloDone instead of
waiting out HostIdle. `TestBridgeKeepsReadingTheECMidFlight` measures both gaps against the rehearsal
stand-in; with either half of the fix removed it reproduces the live 251 ms gap and fails.

The EC is presumably stuck again after this run and needs the EC reset before the next one.

### Run 18 — 2026-09-30 04:01, Run 17's command again, with the mid-flight fix (observed)

`sudo ./goodix-probe --bisect --tls --psk captures/goodix-psk.bin --allow-96 --allow-e4 --allow-a2
--allow-70 --allow-98 --allow-90 --allow-d0 --allow-d4 --steps 96,a8,ae,e4,a2,82,a6,a2,70,98,90`, run by
the user with an external keyboard attached, after an EC reset (log `goodix-bisect-20260930-040117.log`).
**Result: the TLS-PSK handshake completed. The EC and the host share the PSK unsealed from Windows,
`0xd4` was acknowledged, and the internal keyboard stayed alive after every step.** This is the first
completed handshake on Linux, and it settles Phase 5b: the recovered key is the device's key.

- **The EC was fresh:** the health check's `0xa8` answered ACK + `GF_ITE_EC_20063`, and `0xae` answered
  `02 00 31 03 00 00 01 00 00 63 00 … 02 02`, byte for byte Run 17's reply, so the reset before this run
  worked like Run 16's did.
- **The init matched Run 17 step for step:** `0x96` no reply; `0xe4` ACK + 41 bytes (withheld); `0xa2` ACK +
  `01 00 08` both times; `0x82` → `a2 04 25 00` (chip ID `0x2504`); `0xa6` ACK + 64 bytes of OTP (withheld); `0x70` ACK only; `0x98` and `0x90` ACK + `01 01`.
- **The handshake, timed from the host log** (`0xd0` sent at .884, so +0 ms):

  | +ms | direction | record |
  |---|---|---|
  | 17 | EC → host | ClientHello, 47-byte body (same shape as Runs 11 and 17) |
  | 27–30 | host → EC | ServerHello (81), ServerHelloDone (4), one `0xb0` pack each |
  | 34 | EC → host | ClientKeyExchange, identity `Client_identity` |
  | 56 | EC → host | ChangeCipherSpec |
  | 62 | EC → host | Finished (80-byte encrypted body) |
  | 71–74 | host → EC | ChangeCipherSpec, Finished (80), one pack each |
  | 76 | — | openssl reports the handshake complete: 4 records each way |
  | 81 / 88 | host ↔ EC | `0xd4` sent, ACK status `0x01`; no data message follows (5 s timeout) |

  The EC's ChangeCipherSpec came 22 ms after its ClientKeyExchange and its Finished 6 ms after that: the
  vendor log's 22 ms and 27 ms. This is the gap the bridge used to spend waiting on openssl (Runs 11 and
  17). Reading the EC through its flight was the whole fix. The handshake took 76 ms against the vendor's
  1100 ms budget.
- **So the Run 17 hypothesis stands, and nothing else was wrong:** the records, their framing (one pack
  per record) and their contents all passed unchanged, and so did the PSK. An encrypted Finished that
  openssl accepts is only possible with the same key on both ends.
- **`0xd4` answers with an ACK only**, like `0x70`. No capture was requested (`--capture` not given), so
  no application data crossed the session.

**Open after this run:** what state the EC is in now. The handshake finished, but the host dropped the
session without a TLS close. `isTlsConnected` may now be set, and a plaintext command may or may not be
answered. The next run should be `sudo ./goodix-probe --bisect --read-state` on its own, with its replies
compared against Runs 15 and 16, before any step is sent.

### Run 19 — 2026-09-30 04:10, `sudo ./goodix-probe --bisect --read-state` (observed)

Eight minutes after Run 18, apparently in the same boot: the i8042 IRQ count went on from Run 18's 252 to
320 rather than starting over, so no cold power cycle or EC reset came between the two runs. **The health
check passed**: `0xa8` answered ACK + `GF_ITE_EC_20063`, the step's `0xa8` answered the same, and the
keyboard stayed alive. `--read-state` therefore sent no `0xae`, as designed.

- **A completed handshake does not leave the EC stuck**, even one the host dropped without a TLS close.
  A *stalled* one does (Runs 11 → 12, 17). So the EC reset after every `--tls` run is needed only after
  a stall, not after a completed handshake.
- Whether byte 1 of `0xae` (TLS state) is still set is not known from this run. The next init's `0xae`
  step will show it.
- The health check no longer logs "data arrived with no ACK" after reading the ACK itself: the Run 18
  log fix, confirmed live.

### Run 20 — 2026-09-30 04:12, Run 18's command plus `--capture captures/frame-1.pgm --allow-20` (observed)

Two minutes after Run 19, same boot, no EC reset. **Result: the first real frame. The handshake completed
again, `0x20` returned one encrypted image record, it decrypted to 7693 bytes, and the internal keyboard
stayed alive throughout.** Phase 5c is done.

- **`0xae` after a completed handshake:** `02 02 31 03 00 00 01 00 90 63 00 … 04 04`. Compared with the
  EC fresh from a reset (Run 17/18: `02 00 31 03 00 00 01 00 00 63 … 02 02`) and stuck mid-handshake
  (Run 12: `02 08 31 00 00 00 01 00 90 63 … 14 14`):
  - byte 1 is `0x02`, neither `0x00` (fresh) nor `0x08` (stuck), nor the vendor's cold-init `0x11`;
  - byte 8 is `0x90`, as in the stuck state, where the fresh EC has `0x00`;
  - the trailing counter went `02 02` → `04 04` over Run 18's one handshake. That fits `+2` per `0xd0`,
    as `10` → `12` → `14` did over Runs 11 and 12.
  What the bits mean is not known. This is the reply of an EC that answers plaintext and completes a new
  handshake (this run), so it is a healthy state.
- **The init and handshake repeated Run 18 exactly:** the same replies step for step, 4 records each way,
  the EC's ChangeCipherSpec 22 ms after its ClientKeyExchange, and `0xd4` ACK only.
- **`0x20` (payload `01 00`):** ACK after 3 ms, then **one 7753-byte transfer 88 ms after the command**:
  a `b0` pack holding one application-data record with a 7744-byte body, the size the vendor capture shows.
  The next log line (decryption finished) came 2 s later; that is the host side, not the EC.
- **Plaintext: 7693 bytes.** That is 7680 packed samples inside upstream's 8-byte header and 5-byte
  trailer. **This settles the layout question from "How big is an image, really": the frame is wrapped,
  not bare.** The PGM was written to `captures/` (gitignored). Neither the frame nor the
  13 header and trailer bytes were logged, so what they contain is still unknown.
- **The geometry is 64 columns × 80 rows, not 80 × 64.** Read 80 wide, the frame showed diagonal
  streaks with a strong row-to-row pattern: mean |Δ| between vertical neighbours 30.2, horizontal 11.2.
  Read 64 wide, the same bytes give 6.6 vertically and 11.0 horizontally, and show **a clear fingerprint**:
  continuous ridges about 6 px apart, with a ridge ending visible. Column means are flat across each
  4-sample packing group (107.0 / 107.5 / 107.5 / 108.5), so the 12-bit unpacking and sample order
  are right; only the row width was wrong. Upstream's `write_pgm` swaps width and height in its header,
  which is the same correction. The probe now decodes 64 × 80. The existing `frame-1.pgm` had its header
  rewritten; the pixel bytes did not change.
- **`0600` does not hold on this checkout:** `captures/` lies on an NTFS volume (`fuseblk`), which
  ignores Unix modes, and the PGM shows as `775`.

### Run 21 — 2026-09-30 10:02, Run 20's command plus `--wait-finger --allow-32 --allow-34` (observed)

The full init, the handshake, then PLAN.md Phase 5d's loop once round: arm finger-down, capture on touch,
arm finger-up. **Result: the vendor's capture loop works on this machine. The EC reported the touch, the
frame was captured on it, the EC reported the finger gone, and the internal keyboard stayed alive
throughout.** Nothing reset the EC between Run 20 and this run. Nobody knows whether the laptop was
rebooted.

- **`0xae` before the handshake:** `02 02 31 03 00 00 01 00 90 63 00 … 06 06`, Run 20's reply with the
  trailing counter moved from `04 04` to `06 06`. That fits `+2` per `0xd0`: Run 20 sent one. So the EC
  was not reset in the six hours between, and **a third full init and handshake worked without an EC
  reset** (Runs 18, 20 and 21). Every earlier session ended with the process exiting, with no TLS
  close.
- **The init and handshake repeated Run 18 exactly**, down to 4 records each way and a `0xd4` that got
  only an ACK.
- **`0x32` down arm, the catalogue's thresholds `b8c5abb9aab9`:** ACK after 5 ms. **No base-invalid
  event.** The vendor's thresholds from `dump.pcapng` still fit this EC, so the re-arm path is still
  untested live.
- **Finger-down event 10.0 s after the arm**, when the user found the sensor: header `02 00 3f 00`,
  flags `0x3f` (all six zones), readings `[297 271 245 281 229 272]`.
- **`0x20`:** ACK after 3.6 ms, then the 7753-byte image transfer 88 ms after the command, as in Run 20.
  It decrypted to **7693 bytes again**, and the frame shows clear diagonal ridges read as 64 × 80. The
  mean |Δ| between neighbours is 8.8 vertically and 7.4 horizontally.
- **`0x34` up arm `afa295a78da3`:** this is the down reading >> 1 + 27 in all six zones, for example
  297 >> 1 = 148, and 148 + 27 = 175 = `0xaf`. ACK after 5 ms. **Finger-up event 34 ms after the arm**:
  header `00 02 00 00`, readings `[372 399 346 374 343 373]`. These are no-finger readings, so the
  finger was already off when the arm went out. The run therefore shows that the up arm fires on
  untouched readings. It does not show that the arm waits for a finger that is still down.
- **Why the finger was already off:** the plaintext came back 2 s after the image record, as in Run 20.
  `Bridge.ReadApplicationData` forwarded the record to openssl and then blocked in one more device read
  for the whole `DeviceTimeout` (2 s) before it looked for plaintext. **Fixed:** after the first record
  the device is only polled, `min(DeviceTimeout, idle/4)`. `TestPlaintextDoesNotWaitOnTheDevice`
  reproduces the 2.00 s wait without the fix. In the rehearsal, record to plaintext is now 400 ms, which
  is the plaintext idle window.
- **The untouched readings drift only a little.** Halving them gives `bac7adbbabba`, within 1–2 of the
  vendor's arm from 2026-09-19. The readings are 3–4 counts above `dump.pcapng`'s base-invalid readings
  (frame 131).
- **The probe printed the `0xe4` reply (PSK hash) and the `0xa6` reply (OTP) in full.** Both appeared
  in the `transport: RX` line, the `raw` line and the `payload` line. PLAN.md forbids publishing either.
  **Fixed:** `proto.SecretPack` / `proto.SecretReply` is now the one deny list, shared with
  `goodix-pcap`. The probe and all three transports log only the pack header, the command byte and a
  byte count for those replies. This run's log file still holds them, so do not paste it anywhere.

### Run 22 — 2026-09-30 10:45, Run 21's command plus `--touches 3` (observed)

The full init, the handshake, then the capture loop three times in **one TLS session**: arm down,
capture on touch, arm up, wait for the lift, and again. **Result: the EC serves several frames in one
session. All three touches produced a 7693-byte frame, each lift was reported, and the internal keyboard
stayed alive throughout.** This is what an enrolling driver needs; no run before had taken more than one
frame per session.

- **`0xae` before the handshake:** the trailing counter moved from Run 21's `06 06` to `08 08`, one `+2`
  for Run 21's `0xd0`. **A fourth init and handshake without an EC reset** (Runs 18, 20, 21, 22).
- **The handshake repeated Run 18's:** 4 records each way, 108 ms from `0xd0` to complete, `0xd4` got
  only an ACK.
- **No base-invalid event on any of the three down arms**, so the re-arm path is still untested live.
  The first arm used the catalogue's thresholds `b8c5abb9aab9`; the second and third were derived from
  the previous lift's readings (`b9c6acbaabba`, `b8c5abb9aab9`), and the EC accepted both.
- **The three touches:**

  | Touch | Down arm → event | Flags | Down readings | `0x20` → record | Record → plaintext | Up arm → event | Up readings |
  |---|---|---|---|---|---|---|---|
  | 1 | 2.28 s | `0x3d` | `[318 361 231 251 210 291]` | 89 ms | 407 ms | 1.23 s | `[370 396 344 373 343 373]` |
  | 2 | 1.35 s | `0x3d` | `[328 363 209 254 247 259]` | 88 ms | 407 ms | 0.83 s | `[368 395 342 371 340 371]` |
  | 3 | 1.31 s | `0x3f` | `[262 283 267 275 236 267]` | 88 ms | 407 ms | 0.59 s | `[369 396 344 373 341 372]` |

- **The up arm waits for a finger that is still down.** Each lift came 0.6–1.2 s after its arm, not
  34 ms as in Run 21, because the finger was still on the sensor. This was the other thing Run 21 left
  open. The 2 s decrypt delay fix is confirmed live: the plaintext arrives 407 ms after the record, which
  is the bridge's plaintext idle window.
- **Every up arm matches the rule**, and flags `0x3d` show how a zone without the flag gets `0x19`: for
  touch 1 the arm was `ba198e9884ac`. Zone 1 (bit 1 clear, reading 361) got `0x19`, and every other
  zone got reading >> 1 + 27, for example 318 >> 1 + 27 = 186 = `0xba`. Touches 2 (`bf19839a969c`) and
  3 (`9ea8a0a491a0`) check out the same way.
- **The untouched readings are stable to 2 counts** across the three lifts, and within 3 of Run 21's.
- **Every image record was 7744 bytes and decrypted to 7693**, as in Runs 20 and 21. Touch to frame on
  disk took about 530 ms, 400 of them the idle window.
- **The three frames are three different prints**, not one buffer served again. Each shows clear
  ridges, read as 64 × 80, at a different placement (touch 2's ridges run nearly vertical, touches 1
  and 3 run diagonally). The pixel correlation between pairs is only 0.24–0.33, and the range and
  spread are alike (min 52–59, max 172–179, SD 22.6–23.3). So `0x20` takes a fresh image each time.
- **The frames were written root-owned with mode `0600`,** because the run is under sudo, so the user
  who took them could not open them. **Fixed:** the probe now hands its capture and log files to
  `SUDO_UID`/`SUDO_GID`. It now also logs each frame's 8-byte header and 5-byte trailer, so the next
  multi-touch run shows which of those bytes change from frame to frame.

### Run 23 — 2026-09-30 19:31, first C-driver open (observed)

The owner ran the prepared `c1aee77` driver with pinned libfprint
`6f9479c3d55f847c1b3769f28ceb99227f9858cf`. The preceding Go health check at 19:25
returned `GF_ITE_EC_20063` and passed every internal-keyboard check.

- C open passed its own firmware health check, `0x96`, the init firmware read and `0xae`.
- `0xe4` returned ACK status `01`, then a 41-byte payload. Its contents were redacted.
  The C validator rejected the header and stopped open before any reset, TLS request or image request.
- The owner confirmed **both internal and external keyboards still worked** after exit.
- The existing PSK was 32 bytes. Its mode warning was expected: the repository's local
  `fuseblk` mount reported `775` even after `chmod 600`. A synthetic offline check also
  found that this mount could not enforce file `600` or directory `700`; future capture
  images/logs use the owner's ext4 home directory instead.
- There was **no capture or TLS handshake**. libusb printed device-reference warnings on exit;
  those warnings alone do not establish another driver defect or successful interface cleanup.

Offline investigation found that the C validator and Go/C replay fixtures had incorrectly
echoed the request's type into an eight-byte reply header, adding an unexplained trailing byte.
**Run 8 already records the actual nine-byte reply prefix:** `00 03 00 01 bb 20 00 00 00`,
followed by 32 withheld hash bytes. That totals 41 bytes without a trailing byte. Run 23's
redacted log does not independently reveal its prefix; the correction follows Run 8's evidence.
The request remains `03 00 02 bb 00 00 00 00`. The prefix's first byte and reply-type semantics
remain uninterpreted; validate the observed envelope without publishing the hash.

### Run 24 — 2026-09-30 20:19, corrected C init followed by a TLS alert (observed)

The owner used driver `a8a29a3` with the same pinned libfprint. The preceding Go health check
at 20:18 returned `GF_ITE_EC_20063` and passed every internal-keyboard check.

- C's firmware health check and full plaintext init passed. In particular, `0xe4`'s ACK +
  41-byte reply passed the corrected envelope check; both resets, chip ID, OTP, DAC and config
  exchanges completed. Secret replies remained redacted.
- `0xd0` went out at 20:19:43.336. A 52-byte ClientHello record arrived at .351.
  The host sent an 86-byte ServerHello and a 9-byte ServerHelloDone at .351–.352.
  At .353 the EC returned a seven-byte plaintext fatal alert, **`decode_error (50)`**.
- Open stopped before ClientKeyExchange, `0xd4`, the post-handshake MCU check or an image request.
  **Both keyboards still typed after exit**, as confirmed by the owner. The failed handshake
  requires the recovery procedure before another hardware attempt; EC health afterward is unverified.
  The expected existing-key mode warning and libusb exit-reference warnings also appeared.

**Offline investigation, not a confirmed cause:** using a synthetic key and Run 11's documented
extension-free ClientHello shape, the production C TLS helper and Go's native TLS endpoint emitted
identical first flights after normalizing their random/session-ID bytes. No negotiation change or
arbitrary delay was introduced. A transport difference was found: Go completes separate 64-byte
OUT submissions, while this C build submits each entire padded frame (128 bytes for ServerHello).
The successful 256-byte config write argues against a generic multi-packet transport failure;
a TLS-specific assembly/timing difference remains a hypothesis.

The next candidate completes one 64-byte OUT submission at a time, preserving each logical frame's
bytes, one-record-per-pack ordering and overall write budget. Its offline peer now assembles completed
packets, and regressions cover packet sizes, all config-packet failures and budget exhaustion.
Pinned libfprint excludes zero completions from its `short_is_error` check, so the driver explicitly
rejects any packet completion other than 64 bytes. At the time of preparation, this was an
unvalidated candidate; Run 25 below records its hardware result.

### Run 25 — 2026-10-01 05:42, completed 64-byte OUT writes still draw the TLS alert (observed)

The owner reported rebooting, then ran the Go health check at 05:39:08–26. Attach, the
firmware health query and the subsequent `0xa8` step all passed; every internal-keyboard check
passed. This establishes responsiveness after reboot, without assuming a particular power-button
procedure was performed. The owner then used the prepared `e8930b4` packet-write bundle.

- Firmware health and the full C plaintext init passed again. The initial MCU state matched
  the fresh-state shape in Run 18: TLS-connected byte clear and trailing counter `02 02`.
  Secret PSK-hash and OTP replies remained redacted; config returned `01 01`.
- `0xd0` was sent at 05:42:44.810. ClientHello (52 record bytes) arrived at .824;
  the host logged ServerHello (86) and ServerHelloDone (9) at .825. At .827 it read
  a seven-byte plaintext fatal alert, **`decode_error (50)`**, as in Run 24.
- Open failed before ClientKeyExchange, `0xd4`, the final MCU check, finger arming or image
  capture. **Both keyboards still typed after exit**, confirmed by the owner. The known
  PSK-mode warning and libusb exit-reference warnings also appeared. Post-failure EC
  responsiveness was not tested; working keyboards do not establish that the TLS endpoint reset.

**Result:** completed 64-byte submissions did not resolve the rejection. No new packet-size,
negotiation or timing change is justified by this result alone. The log reads IN only after both
server records are sent, so it cannot identify which record prompted the alert.

**Offline follow-up:** the successful Go Runs 18–22 used the historical `openssl s_server`
subprocess (`ec490e0^`), not the current Go memory-BIO endpoint. The earlier C/native comparison
therefore did not compare against the endpoint that succeeded live. A new synthetic probe used
the historical CLI settings on a localhost socket and called only pure TLS/protocol helpers
from the exact owner bundle; no device discovery, GUsb context or USB transport functions were
invoked, and no private artifacts were accessed.
Both emitted the same 86/9-byte first-flight structure after random/session-ID normalization.
An independent framing check verified the bundle helper's 128/64-byte padded packs byte for byte.
This proves helper output for the documented synthetic ClientHello, not what Run 25's EC received.

One meaningful random-field distinction must not be normalized away: the CLI's TLS-1.3-capable
context emits the standard `DOWNGRD\x01` suffix when negotiating TLS 1.2, whereas C's TLS-1.2-only
context does not ([RFC 8446 §4.1.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3)).
This is an observed configuration difference, **not a demonstrated cause**. It does not justify
editing TLS random bytes or changing the protocol ceiling. Independent review found no proven
framing, packet-buffer ownership or callback-lifetime defect. The next investigation needs
sanitized first-flight structure and packet-completion evidence at the actual submission boundary;
length-only logs cannot recover those bytes from this run. Hardware retries are deferred.

**Between Runs 24 and 25** (log `goodix-bisect-20260930-210653.log`), a Go `--read-state` run at 21:06
got no answer to the `0xa8` health check. One `0xae` returned status `0x08` (TLS not connected) and
trailing counter `0x0c`, which is Run 12's stuck mid-handshake state. The internal keyboard worked
throughout. So Run 24's rejected handshake did leave the EC stuck, and the reboot before Run 25 cleared it
(05:39: `0xa8` answered again).

### The gap between the host's TLS records (analysis, 2026-10-01)

The available log timestamps correlate **spacing between consecutive host records** with different
outcomes. They measure logging points, not USB completion times or the EC's parsing interval:

| Handshake | ClientHello → ServerHello | ServerHello → ServerHelloDone | Result |
|---|---|---|---|
| Vendor driver (log above, "The vendor's handshake") | 1 ms | **61 ms** | completed |
| Go probe, Run 18 (`openssl s_server`) | ~10 ms | **~3 ms** (+27 → +30) | completed |
| C driver, Run 24 | ~0 ms | **≤ 1 ms** (.351 → .352) | `decode_error` |
| C driver, Run 25 | ~1 ms | **same logged millisecond** (both at .825) | `decode_error` |

The vendor log also has 66 ms between ChangeCipherSpec and Finished. The hypothesis is that the EC
firmware is still parsing one pack when the next arrives. The accepted config is a single pack,
whereas a TLS flight contains separate packs without command/reply synchronization, so config success
does not exclude a timing problem between packs. **Neither causality nor a required minimum gap is
established.** The successful Go run used a much shorter logged gap than the vendor. Actual C wire
bytes remain unobserved; the matching synthetic framing and the CLI random-suffix distinction in
Run 25 still apply. Timing is not the only unverified difference.

The candidate tests a 60 ms minimum interval (`G5120_TIMEOUT_HS_PACE`) after one host record completes
and before the next is submitted, with IN reads during that interval. Stale messages and zero-length
completions preserve its original monotonic deadline. A partially received TLS record must finish
before more output, even after the interval expires; the total handshake budget bounds that wait.
Complete alerts stop the flight immediately. Counts show handshake progress when an alert was seen;
they do not establish which record caused it. After the last host record, normal EC-flight reads
continue without a pacing interval. TLS bytes, framing and opcode gates are unchanged.

Review regressions reproduced premature writes after stale input and alert prefixes, and writes after
the overall handshake budget expired. The revised candidate checks that budget in every handshake
state and caps its reads and frame writes to the remaining time. The full offline suite now has
245 passing C subtests; hardware timing and resolution of `decode_error` remain unvalidated.

**Owner follow-up, 2026-10-01:** the owner reports another EC crash while running
`dist/goodix-owner-c-pacing/` and is recovering the EC. That bundle was built from the original staged
read-once candidate on `dbdb6d0`, before these review refinements. No final error or sanitized log has
been provided, so the failure point and cause are unknown. Its spacing experiment did not establish
a working C driver. The reviewed source is not represented by that bundle, and further hardware
attempts remain deferred pending diagnostics and review.

### Recovering the EC (researched offline, 2026-09-30)

The question after Run 14: how do you reset an EC the power-button procedure does not reset? **Answered by
Run 16: shut down, leave the charger plugged in, hold the power button 40 s** (item 2, variant 1). The rest
of this section is the research that led there, and the fallbacks if it ever stops working.

**The power-button procedure has reset the EC once, not every time.** The `0xae` trailing counter only
ever rose: `04`, `0a`, `0e` in the Windows captures of 2026-09-19, then `10` (Runs 6–10), `12` (Run 11)
and `14` (Run 12). `isTlsConnected` also stayed set through every cold power cycle before Run 11. The
Windows driver log shows exactly **one** real EC reset: status `0x11`, TLS down, counter back at `02 02`, at
log time 2026-09-19 20:46:41 (record #249554). That log's clock runs two hours behind Linux's CEST, so this
is 22:46 CEST. It is three minutes after the shutdown that followed Run 4's wedge (22:43:09), and inside the
gap the user described as a cold power cycle.

That one reset had a wedged EC behind it: Run 4's `0xe4` froze the firmware's main loop. Since Run 12 the
firmware runs normally — the keyboard, the battery refresh counter and USB enumeration all work — and it
is only waiting inside a handshake. **Hypothesis:** in 2026-09-19 the EC's own watchdog, not the power
button, did the reset. A running EC would not trip it, and a power-button press is just a shutdown to it.

**The vendor has no reset for this part.** `gfusb.dll` has `HardResetMcu`, which goes through an ACPI
`_DSM`, and logs `not support hard reset for EC projects %d`. `docs/acpi.md` found no power control for
the sensor's port. USB re-enumeration happens on every boot, and Run 14 followed one. The
driver's own recovery is to retry the init (`RetryCountForComminInit`, `Init: TLS Handshake Failed in %d
try`), but the Windows log never shows a failed handshake, so it holds no recovery to copy.

**ITE resets are firmware-driven.** In the Chromium EC `it83xx` port, a reset is a watchdog key write or
the WRST# pin. There is no fixed hardware timer that resets the chip when the power button is held. How
long a hold resets the EC, if any hold does, is up to Huawei's firmware. Other vendors disagree even on
the charger: ASUS keeps it **plugged in** and holds for 40 s on some models, while the common advice is
to unplug it and hold for 30 s. No Huawei source describes an EC reset.

What is left, least invasive first:

1. **Read the state first** — `--bisect --read-state` (`docs/bisect-runbook.md`). It sends one `0xae`
   after the failed health check. Status `0x08` and a counter above `0x14` mean the stuck handshake is
   still there. A counter below `0x14` means the EC *was* reset and something new is wrong.
2. **Power-button variants**: charger plugged in with a 40 s hold, and charger unplugged with a 60 s
   hold. Run `--read-state` after each. The counter is what shows whether one worked.
3. **Disconnect the internal battery**: bottom cover off, battery connector unplugged, charger unplugged,
   power held 30 s, a few minutes' wait. This is the one reset that certainly takes the EC's supply away.
4. **End the handshake from the host** with a TLS fatal alert in one `0xb0` pack. An alert is how TLS ends a
   handshake, and the EC's stack is built to receive one. The vendor strings (`got an alert message`,
   `is a fatal alert message`) are the driver's mbedTLS, so this is inference, not an observation of the EC.
   It would be a new live code path, not built yet. Resuming Run 11's handshake instead is not possible:
   the log keeps the ServerHello's length, not its bytes.
5. **A Huawei BIOS/EC update**, if one newer than BIOS 1.08 / EC 1.8 exists. An EC flash reboots the EC,
   but the update runs from Windows (see below).

**Do not boot Windows while the EC is stuck.** When it starts, the Goodix driver sends the full init and
retries it, and the full init sent into this state is exactly what killed the keyboard in Run 12.

### The vendor's handshake, read from the driver log (observed, 2026-09-30)

Run 11's framing question was marked unanswerable because `dump.pcapng` holds no host→device TLS pack.
**The driver log answers it.** Its init at 2026-09-19 23:25:41 (log clock; records #263055 onward, read
with `goodix-evtx -from "2026-09-19 23:25:38" -to "2026-09-19 23:25:45" -text`) logs every send and
receive of a handshake that completed in 172 ms:

```
time (log)     direction       record                               pack
23:25:41.496   host → EC       0xd0 (no ACK waited for)             a0 …
23:25:41.510   EC → host       ClientHello, 47-byte body            type 0xb, 52 bytes
23:25:41.511   host → EC       ServerHello, 86-byte record          "SENT DATA LEN: 86, 90"
23:25:41.572   host → EC       ServerHelloDone, 9-byte record       "SENT DATA LEN: 9, 13"
23:25:41.574   EC → host       ClientKeyExchange, identity "Client_identity" (26 bytes)
23:25:41.596   EC → host       ChangeCipherSpec (6 bytes)
23:25:41.601   EC → host       Finished, 80-byte encrypted body (85 bytes)
23:25:41.601   host → EC       ChangeCipherSpec, 6-byte record      "SENT DATA LEN: 6, 10"
23:25:41.667   host → EC       Finished, 85-byte record             "SENT DATA LEN: 85, 89"
23:25:41.668                   "TLS handshake over successfully."
```

What it settles:

- **The vendor sends one pack per record**, in both directions: ServerHello and ServerHelloDone are two
  sends, each wrapped in its own 4-byte pack header (86 → 90, 9 → 13). That is **Run 11's framing**. The
  one-pack-per-flight change made after Run 11 moved *away* from the vendor, so it is reverted: the bridge
  sends one pack per record. (`--tls-coalesce-flight` kept the other framing for comparison until Run 18 settled it; it was removed on 2026-09-30.)
- **The server flight's contents match openssl's.** mbedTLS's ServerHello is 81 bytes of body, exactly
  the length of openssl's (32-byte session id plus `renegotiation_info`, answering the EC's SCSV). There
  is no ServerKeyExchange in the vendor's flight either: ServerHello is followed directly by the 4-byte
  ServerHelloDone. So neither suspect Run 11 listed for the contents holds up.
- **The EC's side is minimal**, as its ClientHello suggested: ClientKeyExchange carries only the PSK
  identity `Client_identity`, and the EC sends its three records as three packs.
- **Padding matches too.** The vendor's OUT transfers are padded to 64 bytes (see "Read back from the
  captures"), and so are ours.

*Corrected by Run 17: the paragraph below overstates `0xe4`. Both stalls are explained by the bridge not
reading the EC for 250 ms at the moment the EC sends its next record; see Run 17.*

**So what differed in Run 11 is the init, not the TLS.** The vendor's init before `0xd0` is
`96, a8, ae, e4, a2, 82, a6, a2, 70, 98, 90` in every one of the nine logged inits. Run 11 sent all of
that **except `0xe4`** (`preset_psk_read`, the read of the PSK hash), which was left out after the
empty-payload wedges and proved safe with the vendor payload in Run 8. **Hypothesis, not observed:** the
EC loads or checks its PSK slot while answering `0xe4`, and without it the TLS stack stalls when it has to
build its ClientKeyExchange, which is the first message that needs the key slot. It fits the stall's
position exactly: the EC went quiet at the one point where the vendor's EC sends ClientKeyExchange.
Timing is the other remaining difference, and a small one: the vendor answered the ClientHello in 1 ms,
Run 11 in 8 ms, well inside the vendor's own 1100 ms handshake budget (`time_wait_for_tls 1100`).

The next `--tls` run therefore sends the vendor's init in full, `e4` included (`docs/bisect-runbook.md`),
with the vendor's framing. A live `--tls` run whose steps leave out part of that init now logs a warning,
and a stall names the missing commands first (`missingFromVendorInit` in `cmd/goodix-probe/tls.go`).

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

Device facts, from the log: **chip ID `0x2504`**, "ChicagoHS", sensor type 12, **80 × 64 pixels** (*Run 20: stored as 64 samples per row, 80 rows*)
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
| 4 | `e4` read production data | `03 00 02 bb 00 00 00 00` | ACK, 41 bytes: Run 8's nine-byte prefix `00 03 00 01 bb 20 00 00 00`, then a 32-byte PSK hash |
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

64 × 80 = 5120 samples at 12 bits (orientation from Run 20), packed four samples per six bytes, is **7680 bytes exactly** — the
bottom of that range, reached with a full 16-byte padding block. Upstream's 8-byte header and 5-byte
trailer would make 7693, also inside it.

So the record length independently corroborates the 5120-sample geometry with upstream's 12-bit packing,
which until now rested only on the chip ID and upstream's own tables. It cannot distinguish a bare
frame from one with upstream's header and trailer: both fit. Nothing here is decoded — this is
arithmetic over lengths observed on the wire, and it stays a hypothesis until a plaintext is measured.

**Reproduced, not just calculated (2026-09-20).** The arithmetic above was checked against a real
implementation rather than done twice. Encrypting exactly 7680 bytes with suite `0x00ae` under openssl
3.5.5 produces a record whose header is `17 03 03 1e 40` and whose total size is 7749 bytes, inside a
`b0` pack of 7753 — **the same lengths the vendor's traffic shows in `dump.pcapng`, byte for byte**. This
is the `internal/session` rehearsal (`TestBridgeDecryptsApplicationData`, and
`goodix-probe --bisect --replay --tls --capture`), where a synthetic 7680-byte frame goes through a real
TLS-PSK session.

That closes the padding question — 7680 plaintext really does produce a 7744-byte body under this
suite — but it does **not** settle bare against wrapped: 7693 bytes pad to the same 7744. Only a measured
plaintext does, which is what Phase 5c is for. `internal/image.TrimFrame` decides from the length that
arrives and refuses anything that matches neither, rather than assuming an offset — a frame decoded from
the wrong offset still looks like a fingerprint.

### Capture loop (steady state, `dump.pcapng`)

```
TX 32 FDT down  [0c 01 + 6 × (80 xx) + uint16 timestamp]  → ACK … RX 32 event [02 00 ff 00 + 6 × u16]
TX 20 get image [01 00]                                   → ACK, RX b0 pack (TLS image)
TX 34 FDT up    [0e 01 + 6 × (80 xx)]                     → ACK … RX 34 event on lift [00 02 00 00 + 6 × u16]
   (optionally: TX 36 FDT manual [0d 01 + 6 × (80 xx)]    → ACK, RX 36 [00 01 ff 00 + 6 × u16]; TX 20 again)
```

`ff` is a flags byte (seen: `2f`, `37`, `3d`, `3e`, `3f`), probably a touched-zone mask.

The driver's own legend: FDT mode "1Down2Up3Manual" = `0x32`/`0x34`/`0x36`. The six `80 xx` pairs are
per-zone thresholds derived from the last FDT readings — the exact rules are in "Finger detection: where
the thresholds come from" below. An `0x32` event starting with
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

### Finger detection: where the thresholds come from (observed, 2026-09-30)

Until now the six `80 xx` bytes of an arm were "derived from the last FDT readings (hypothesis)". The
derivation is now pinned, from two independent sources that agree:

- **The wire.** Every arm in `dump.pcapng` except the first (whose inputs predate the capture) was
  recomputed from the event before it: **68 of 68 match** (25 `0x32`, 43 `0x34`).
- **The driver log.** Its `fdt_upbase[i]` lines print the up thresholds (as `0xTT80`, i.e. the two wire
  bytes read little-endian) next to their inputs: `received fdt base::<the down event's six readings>`,
  `diff_use 27` and `touchflag`. It also gives the margin's origin at init: `default fdt delta 21`, then
  `OTP tcode 272, fdt delta 27`.

The rules, with `z[i]` the event's `uint16` readings and `flags` its third header byte:

| arm | derived from | threshold for zone *i* |
|---|---|---|
| `0x32` down | readings with **no finger**: an up event or a base-invalid event | `z[i] >> 1` |
| `0x34` up | the **finger-down** event | `(z[i] >> 1) + 27` if bit *i* of `flags` is set, else `0x19` |

So `flags` really is the touched-zone mask: bit *i* clear means the finger missed zone *i*, and that
zone's up threshold drops to `0x19`. 27 is this device's delta from its OTP; how the OTP yields it is
not known, so the code uses the observed constant (`proto.FDTDeltaObserved`).

**Correction: a base-invalid event is not zeroed.** Its header is `80 00 00 00`, but its six readings are
the EC's current untouched values (e.g. `0x171 0x18c 0x156 0x172 0x154 0x172`), and the driver re-arms
from exactly those. That is how a stale base heals itself: the arm after a finger that was not quite
lifted (`up` readings `0x151 0x186 0xfb …`) has thresholds far from the true base, the EC answers
base-invalid about 30 ms later, and the next arm is right.

The untouched readings are stable across weeks: the 2026-08-15 log and the 2026-09-19 capture differ by
a few counts per zone. The vendor's steady down arm, `b8 c5 ab b9 aa b9`, is therefore where
`--wait-finger` starts; if it no longer fits, base-invalid corrects it. The `uint16` at the end of a
`0x32` arm is a millisecond counter: frame 2 to frame 27 advance it by 3400 over 3.401 s.

Implemented as `proto.DownThresholds` / `proto.UpThresholds` (tested against capture pairs), and used by
`goodix-probe --wait-finger` (PLAN.md Phase 5d), which runs `32` → `20` → `34` once. Not yet run live.

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

**Structure — interpretation, not fact.** 29-byte header, then 48 four-byte slots of
`[register LE16][value LE16]` of which **the last three are zero-filled, so 45 are used** — a
fixed-size table partially filled, not 48 live entries — then a 3-byte tail. It is a write **script, not a map**: registers
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
