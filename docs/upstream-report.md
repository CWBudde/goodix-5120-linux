# Upstream report — drafts, not posted

Working file for `PLAN.md` Phase 2 ("Publish the findings"). It holds two ready-to-post drafts and the
decisions that have to be made before either goes out.

**Nothing in this file has been published.** No issue was opened, no comment posted, no mail sent. The
drafts are written to be copied out and posted by the repository owner, after the decisions below are
settled.

Each draft is self-contained: it repeats what a stranger needs and refers to nothing inside this
repository that a stranger cannot open.

Conventions inside the drafts follow [`docs/protocol.md`](protocol.md):

- **observed** — measured on this machine's wire, or read out of the vendor driver's own debug log or
  binary on this machine.
- **transcribed** — taken from upstream `goodix-fp-dump` Python source, believed accurate for the 5110,
  only *assumed* for the 5120.
- **hypothesis** — inference. Not measured.

---

## DECIDED — the 224-byte `0x90` config IS published

The repository owner decided on 2026-09-20 to publish the bytes. Both drafts below carry them in full,
together with the decoded register entries. This section records the basis, because both drafts state
it in short form and a maintainer accepting the contribution should be able to see the reasoning.

**Why it is publishable.**

1. **It is very likely not protected expression in the first place.** Copyright protects expression,
   not function. These 224 bytes are a table of hardware register addresses and the values the chip
   requires — content dictated by the hardware, with no room for authorial choice. The EU standard is
   the author's own intellectual creation (*Infopaq*, C-5/08), and *SAS Institute v World Programming*
   (C-406/10) held that a program's functionality, its language and its data formats are not protected
   as expression. A configuration table sits on the unprotected side of that line.
2. **If it were protected, the interoperability exception covers it.** Directive 2009/24/EC Art. 6,
   transposed in Germany as § 69e UrhG, permits reproducing and translating code where indispensable to
   obtain the information needed to make an independently created program interoperable. Art. 6(2)(b)
   restricts passing that information to others *"except when necessary for the interoperability of the
   independently created computer program"* — so disclosure for that purpose is contemplated by the
   exception, not merely tolerated. § 69e is unwaivable: § 69g(2) UrhG voids contrary licence terms.
   Art. 5(3) / § 69d(3) separately covers observing and testing the program, which is what the USB
   captures and the debug-log analysis are.
3. **The conditions of Art. 6(1) are met on the facts here.** The work was done on a lawfully owned
   machine with a lawfully licensed copy of the driver; the information was not otherwise available
   (three attempts to capture it on the wire failed for a tooling reason, and the vendor's own debug log
   truncates the payload); it is confined to the part necessary for interoperability — one configuration
   frame, not the driver's code; and it is used solely to make an independent Linux implementation work
   with the device, not to build a competing driver.

**What this basis does *not* rest on.** Not the EU right-to-repair directive ((EU) 2024/1799) and not
the Ecodesign rules. Those place obligations on manufacturers around spare parts and repair
information; they do not grant third parties a right to redistribute extracted driver data. They are
the wrong authority to cite here and citing them would only cloud the argument above.

**Precedent in the receiving communities.** `goodix-fp-dump` already carries protocol constants
extracted from Goodix's Windows drivers, so this is an established norm there rather than a novel ask.

**This is a considered position, not legal advice**, and it was not written by a lawyer. It is recorded
so that anyone accepting the contribution can see what it is based on and reach their own view.

**Consequence for the repository — and a correction.** `cmd/goodix-probe/vendor.go` carries these
bytes, and the repository **was already public** at `https://github.com/CWBudde/goodix-5120-linux` when they
were committed, with auto-push on commit. So they went public at commit time, before this decision was
recorded rather than after it. The decision above ratifies that; it did not gate it. Anyone reasoning
about this repository should start from "everything committed is already published", not from "this
may be published later".

**Still withheld, on grounds that have nothing to do with copyright:** the `0xe4` PSK hash, every byte
of `Goodix_Cache.bin`, the DPAPI master-key GUID, the OTP, and the OTP-derived `0x98` DAC values. Those
are per-device secrets and calibration data — they are this unit's, useless to anyone else, and two of
them are security material.

---

## CHECK BEFORE POSTING — smaller calls, also not made here

1. **`0x98 set_dac` payload.** The vendor sends 8 bytes that its own log says are *derived from the
   OTP*. The OTP is on the never-publish list, so the drafts describe the frame ("8 bytes, computed
   from the OTP, therefore per-unit") and do not print the bytes. If the owner judges DAC values not to
   be OTP material, they can be filled in; the value is low, since they are this unit's.
2. **The unsolicited `0x32` frame, printed in full in Draft A.** It is an FDT-down (finger-detect)
   event: six per-zone `uint16` readings, not image data, and it is already recorded verbatim in
   `FINDINGS.md` and `docs/protocol.md`. Judged non-biometric here, but it is the one place a draft
   prints sensor readings, so it is called out rather than assumed.
3. **Short verbatim strings from the vendor driver's debug log** — "not to send nop for ITE EC
   projects", "no firmware update for EC projects". Quoted in both drafts because they are the evidence
   for the `nop` rule and cannot be paraphrased without losing that. Short quotation from a log the
   owner's own machine produced; flagged only for completeness.
4. ~~**Board identifier.**~~ **Resolved 2026-09-20 from DMI:** `product_name=HVY-WXX9`,
   `board_name=HVY-WXX9-PCB`, `board_version=M1060`. Not a contradiction — two different DMI fields,
   loosely labelled. The drafts use the product name, which is the one a reader can match against.
5. ~~**The full `lsusb -v` dump.**~~ **Done 2026-09-20** — the real unprivileged output is in Draft B,
   verbatim. It agrees with the abridged fields this repository already held, and added three facts
   nobody had recorded: Full Speed negotiation, the malformed `bmAttributes 0x60`, and Remote Wakeup.
6. ~~**The public repository.**~~ **Resolved: it is already public** —
   https://github.com/CWBudde/goodix-5120-linux, since 2026-08-17. Both drafts can link it
   directly; the "may follow" hedging and the URL placeholders should be replaced with the real link.
7. **Contact and attribution.** Neither draft signs itself or offers a way to reach the author. Add
   whatever is appropriate for each tracker.

---

## Pre-post checklist

- [x] The `0x90` decision is made (publish), and both drafts carry the bytes and the entry table.
- [ ] No PSK material: no PSK hash from the `0xe4` reply, no bytes of `Goodix_Cache.bin`, no DPAPI
      master-key GUID.
- [ ] No OTP bytes, including the ASCII prefix, and no `0x98` DAC values unless item 1 above is decided.
- [ ] No capture files attached, and nothing derived from a fingerprint image.
- [x] Draft B carries a real `lsusb -v` dump, not a reconstruction.
- [ ] Cross-links between the two posts filled in once the first one has a URL.
- [ ] Dates, counts and the recovery procedure re-read against `docs/protocol.md` — they have drifted
      in this repository before (see the report accompanying this file).

---
---

# Draft A — for `goodix-fp-linux-dev/goodix-fp-dump`

**Destination:** a GitHub issue or discussion at <https://github.com/goodix-fp-linux-dev/goodix-fp-dump>.
Discussion is probably the better fit: this is a report and two questions, not a bug in their code.

**Before posting:** settle the `0x90` decision above; fill or delete the two placeholders; add the
libfprint link once Draft B is posted.

---

## Title

`27c6:5120` on Huawei MateBook is a USB-attached **ITE EC bridge**, not the sensor MCU — protocol
divergences from `driver_51x0.py`, and a warning about `0xe4`

## Body

### Warning first: `0xe4` with an empty payload wedges the EC — and the laptop's keyboard dies with it

On this machine, sending `preset_psk_read` (`0xe4`) **with an empty payload** stops the embedded
controller dead. The EC acknowledges the frame within a few milliseconds and then never speaks again —
and because the same controller drives the laptop's internal keyboard over i8042, the keyboard stops at
the same moment. **Observed three times** (2026-08-17, 2026-09-19 18:27, 2026-09-19 22:41).

The exact frame that does it, as this project sent it — outer pack plus inner message, no payload:

```
a0 04 00 a4   e4 01 00 c5
```

- **It needs nothing before it.** The third run sent only this: attach the device, send that one frame,
  nothing else. ACK after 4 ms, then silence, then a dead keyboard. No `nop`, no `firmware_version`
  first. One frame is sufficient. (observed)
- **The opcode is not the hazard; the missing argument is.** The Windows vendor driver sends `0xe4`
  with an 8-byte argument in every one of its initialisations and gets an ACK plus 41 bytes of data
  back. (observed, from the vendor driver's own debug log)
- **The kernel logs nothing.** Not one i8042, atkbd or USB message between the frame and the shutdown.
  The device stays enumerated. From Linux's side nothing has happened, which is why it took three
  rounds to attribute. (observed)
- **The EC stops serving i8042 within tens of milliseconds.** Twice the interrupt counter showed a key
  *make* delivered and its *break* never arriving — the EC died between press and release, about 20 ms
  after accepting the frame. (observed)
- **Recovery is a cold power cycle and nothing less:** full shutdown, charger unplugged, power button
  held ~30 s. A warm reboot does not reset the EC. Unbinding and rebinding `atkbd` recreates the input
  node correctly and still no scancodes arrive, because the EC is not sending any. (observed)
- **There is no software recovery to find**, at least on this machine. Its ACPI tables give the
  sensor's USB port `_ADR`, `_UPC` and `_PLD` and nothing else — no `_PRW`, no power resource, no
  `_DSM` — so nothing in firmware can cut power to the port or reset the sensor. (observed)
- **Why the EC blocks is a hypothesis**, not a finding: presumably its handler reads an argument that
  is not there and blocks its main loop after having already queued the ACK. The same pattern fits
  `read_otp` (`0xa6`) with an empty payload, which drew no reply at all, while the vendor's `a6 00 00`
  gets an ACK plus 64 bytes.

**Practical rule, if you touch one of these parts: send every command with the payload the vendor sends
with it. Never send a bare opcode to find out what it does.** On a discrete Goodix MCU an empty frame
costs you a sensor; on an EC part it can cost you the machine's keyboard until you can power-cycle it.

Two further don'ts for any ITE EC part:

- **Do not run `driver_51x0.main()`.** It flashes `GF_ST411SEC_APP_12117.bin` over IAP when the running
  firmware string does not match — and on this device it never matches, so the condition holds and the
  script would attempt the write. The target here is an EC that also runs the keyboard.
- **Do not send `nop` (`0x00`).** The vendor driver deliberately does not: its own log says *"not to
  send nop for ITE EC projects"*. On this device `nop` draws no reply at all — no ACK, no data — in
  three separate live runs. (observed)

### The device

| | |
|---|---|
| USB ID | `27c6:5120`, `bcdDevice 2.00` |
| Machine | Huawei MateBook, DMI product `HVY-WXX9` |
| OS during the runs | Ubuntu 26.04, kernel 7.0.0-29-generic |
| Firmware string (`0xa8`) | `GF_ITE_EC_20063` |
| Chip ID (`0x82` read register) | `0x2504`, which the vendor driver calls "ChicagoHS", sensor type 12 |
| Sensor geometry | **80 × 64** per the vendor driver — *not* upstream's `SENSOR_WIDTH 80` / `SENSOR_HEIGHT 88` |

```
bNumInterfaces 2
  interface 0   class 2  (Communications)   EP 0x82 IN,  8 bytes
  interface 1   class 10 (CDC Data)         EP 0x01 OUT / EP 0x83 IN, bulk, 64 bytes
```

Two things worth flagging against this repository's `run_5120_spi.py`:

1. **This `5120` is USB-attached, not SPI.** There is no `/dev/spidev*` on the machine at all, so the
   SPI path is inapplicable here. The PID alone does not tell you the wiring. (observed)
2. **What answers is not the sensor MCU.** `GF_ITE_EC_20063` is an **ITE embedded controller** acting
   as a bridge, where the 5110 reports `GF_ST411SEC_APP_12117`. It speaks the 51x0 framing faithfully,
   and an unknown part of the command set beyond that is EC-specific. On this laptop the same EC also
   drives the internal keyboard over i8042 and is reachable through three separate host interfaces —
   the USB device, the i8042 keyboard controller (`PNP0303`, ports `0x60`/`0x64`, IRQ 1) and the ACPI
   EC channel (`PNP0C09`, GPE 3). A command on one silenced another. (observed)

### Framing: confirmed, exactly as documented here

The two nested framings transcribed from `goodix.py` are **correct for this device** (observed; every
pack and message checksum verifies in every live run and in four USB captures of the vendor driver,
382 decoded frames, 0 failures):

- pack `[flags:1][length:2 LE][checksum:1][payload:N]`, `checksum = sum(bytes[0:3]) & 0xff`
- message `[cmd:1][length:2 LE][payload:N][checksum:1]`, length = `len(payload) + 1`,
  `checksum = (0xaa - sum(bytes[0 : 2+length])) & 0xff`

One incidental note for anyone parsing vendor captures: the Windows driver does not zero the padding of
its 64-byte OUT transfers — stack bytes leak in. Ignore everything past the pack length. (observed)

### Four divergences from `driver_51x0.py`

All four are observed on this device, and all four are handled in this project's code.

**1. ACKs are a `0xb0` message, not `cmd | 0x01`.** The acknowledgement is a distinct message with
`cmd = 0xb0` whose payload is `[original_command][status]`:

```
sent 0xa8  →  b0 03 00 | a8 01 | 4e      ACK for 0xa8, status 01
sent 0xe4  →  b0 03 00 | e4 01 | 12      ACK for 0xe4, status 01
```

Keep this apart from the *pack*-layer flag `0xb0` (`FlagTLSData`). Same value, different field,
different layer. `0xb0` is receive-only — there is no reason to ever send it.

**2. Each command produces two transfers: ACK first, then the data response, separately.** A reader
that reads once per command runs permanently one transfer behind, and the symptom is confusing — the
firmware string arrives while you are reading for the *next* command. Read until the data message
arrives or the device goes quiet, and drain the IN endpoint before you exit.

Two exceptions on record: `0xae` (get MCU state) answers with its 20-byte state and **no ACK**, and
`0xd0` (request TLS) gets no ACK either — the EC simply starts the handshake.

**3. The EC emits an unsolicited `0x32` on attach.** It arrived before any command could have caused
it:

```
32 11 00 | 02 00 2f 00 1e 01 38 01 ff 00 f7 00 3f 01 34 01 | 73
```

It is an **FDT-down (finger-detect) event**, in the same shape the vendor driver receives:
`02 00 <flags> 00` then six little-endian `uint16` zone readings. The explanation is that the Windows
driver leaves the EC **armed** in FDT-down mode when it goes idle and never disarms it, so a machine
rebooted from Windows into Linux meets an EC that is still armed and reports the next touch to whoever
reads the endpoint. Any reader has to tolerate unsolicited messages. (observed; the "left armed"
explanation is observed in the driver's own behaviour, the attribution of this particular frame to it is
a hypothesis)

**4. `read_otp` (`0xa6`) with an empty payload draws no reply at all** — no ACK, no data. With the
vendor's `a6 00 00` it returns an ACK and 64 bytes. Same shape as the `0xe4` problem, without the
consequences. (observed)

### The vendor init sequence, plaintext part

From the vendor driver's ETW debug channel (`Goodix-FingerprintProvider/Debug`), which logs every frame
it sends and receives in hex. The log covers 2026-08-15 to 2026-09-19 and holds 18 initialisations, **9
of them complete**; the sequence below is identical in all 9. The most recent was re-read frame by
frame, reply lengths included. (observed)

Payloads are message payloads, checksum omitted. "ACK" means a `b0` message `[cmd] 01`.

| # | TX | payload | reply |
|---|---|---|---|
| 1 | `96` enable chip | `01 02` | none; the driver does not wait for one |
| 2 | `a8` firmware version | `00 00` | ACK, `GF_ITE_EC_20063` |
| 3 | `ae` get MCU state | `55` + `uint32` LE host timestamp (ms) | **no ACK**, 20-byte state |
| 4 | `e4` read production data | `03 00 02 bb 00 00 00 00` | ACK, 41 bytes |
| 5 | `a2` reset | `01 14` | ACK, `01 00 08` |
| 6 | `82` read register | `00 00 00 04 00` | ACK, `a2 04 25 00` → chip ID `0x2504` |
| 7 | `a6` read OTP | `00 00` | ACK, 64-byte OTP (~35 ms) |
| 8 | `a2` reset | `01 14` | ACK, `01 00 08` |
| 9 | `70` MCU to idle | `14 00` | ACK |
| 10 | `98` set DAC | 8 bytes, computed from the OTP (per-unit; not reproduced here) | ACK, `01 01` |
| 11 | `90` upload config | 224 bytes — see below | ACK, `01 01` |
| 12 | `d0` request TLS | `00 00` | no ACK; the EC opens the handshake |
| 13 | `d4` TLS established | `00 00` | ACK |
| 14 | `ae` get MCU state | as #3 | state with `isTlsConnected = 1` |
| 15 | `36`, `50`, `36`, `82 00 82 00 02 00`, `20`, `36` | calibration | — |
| 16 | `32` FDT down | armed; the driver now waits for a finger | ACK, then an event on touch |

Notes:

- **`0xe4`'s argument is `data_type = 0xbb020003` little-endian, then a `uint32` length of 0.** The
  41-byte reply is that type, a length `0x20`, and a 32-byte hash of the device's PSK (that accounts
  for 40 of the 41; the last byte is unexplained). The hash is device-specific and is not reproduced
  here.
- **`0x50` appears in the driver log only.** It shows up zero times in either USB capture. Treat it as
  unconfirmed on the wire.
- **`0xd2` does not appear anywhere** — not in the log, not in either capture.
- **No firmware-related opcode is ever sent:** none of the 9 complete inits uses `0xe0`, `0xf0`,
  `0xf2`, `0xf4` or `0xf6`. The driver's log says *"no firmware update for EC projects"*. (observed)
- **`96 enable_chip` takes a boolean.** The init sends `01 02`; a Device Manager *Disable* sends
  `00 02` — the same command with its first byte cleared — then one `ae`, then the driver unloads.
  So upstream's name for it is right, and there is a quiesce command. (observed, twice)
- **On idle the driver sends nothing at all.** No shutdown, no D3Final sequence; it stops reading and
  leaves the EC armed with its TLS session up. The EC tolerates the host going away. (observed)

### `0x90 upload_config_mcu` — 224 bytes, recovered

The one frame of the init that a debug log cannot give you (it truncates the payload to its first 57
bytes). It was recovered statically from the vendor DLL. (observed)

- Payload is **224 bytes**; the complete frame on the wire is **232 bytes**: pack `a0 e4 00 84`, message
  header `90 e1 00`, payload, message checksum `8f`.
- **It is a write script, not a register map.** Structure (interpretation, not fact): a 29-byte header,
  then 48 four-byte entries of `[register LE16][value LE16]`, then a 3-byte tail. Several registers
  recur up to three times with different values, so **order is significant and it cannot be replayed as
  an unordered set**. The 29-byte header does not fit the entry pattern and is not decoded.
- `sum(payload) & 0xff == 0xaa` — the vendor's own message-checksum convention, which is what pins the
  224-byte boundary.
- Four independent checks agree, each of which would fail on a window off by a single byte: 19
  byte-identical occurrences in the DLL; its first 57 bytes match what the debug log shows in all nine
  complete inits over a month; the checksum identity above; and re-encoding it with an independent
  implementation of the framing reproduces the logged first 64 bytes byte for byte, pack checksum
  included.

**Provenance and basis for sharing this.** These bytes were obtained by static analysis of the vendor's
Windows driver on hardware I own, under the interoperability exception in Directive 2009/24/EC Art. 6
(§ 69e UrhG in Germany), for the sole purpose of making an independent Linux implementation work with
the device. They are a hardware register/value table rather than program logic, which on the *SAS
Institute* (C-406/10) reasoning is unlikely to be protected expression at all. Nothing of the driver's
code is reproduced here, and no per-device secret is included — the device PSK hash, the OTP and the
sealed key blob are all deliberately withheld. If a maintainer would rather this material were not
carried in your tracker, say so and I will remove it.

**The payload (224 bytes, hex):**

```
7011607100712c9d1cb918d100d100d100ba000180ca000400840015b3860000
c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000
b6980000009a000000d2000000d4000000d6000000d800000050000105d00000
00700000007200785674003412200010402a0182032200012024001400800001
005c000001560004205800030232000c02660003007c000058820080152a0108
005c008000540010016200040364001900660003007c0000582a0108005c0000
015200080054000001660003007c000058000000000000000000000000007815
```

The complete frame on the wire is 232 bytes: pack `a0 e4 00 84`, message `90 e1 00`, the 224 bytes
above, then the message checksum `8f`.

**Decoded as `[register LE16][value LE16]` entries** (interpretation, not fact — the byte sequence is
what is observed). Bytes 0..28 are a header that does not fit the entry pattern and is not decoded;
bytes 29..220 are 48 four-byte slots of which the last three are zero-filled, so **45 slots are
used**; bytes 221..223 are a 3-byte tail.

```
0x0086 = 0xc400  0x0088 = 0xba00  0x008a = 0xb200  0x008c = 0xaa00
0x008e = 0xc100  0x0090 = 0xbbbb  0x0092 = 0xb1b1  0x0094 = 0xa800
0x0096 = 0xb600  0x0098 = 0x0000  0x009a = 0x0000  0x00d2 = 0x0000
0x00d4 = 0x0000  0x00d6 = 0x0000  0x00d8 = 0x0000  0x0050 = 0x0501
0x00d0 = 0x0000  0x0070 = 0x0000  0x0072 = 0x5678  0x0074 = 0x1234
0x0020 = 0x4010  0x012a = 0x0382  0x0022 = 0x2001  0x0024 = 0x0014
0x0080 = 0x0001  0x005c = 0x0100  0x0056 = 0x2004  0x0058 = 0x0203
0x0032 = 0x020c  0x0066 = 0x0003  0x007c = 0x5800  0x0082 = 0x1580
0x012a = 0x0008  0x005c = 0x0080  0x0054 = 0x0110  0x0062 = 0x0304
0x0064 = 0x0019  0x0066 = 0x0003  0x007c = 0x5800  0x012a = 0x0008
0x005c = 0x0100  0x0052 = 0x0008  0x0054 = 0x0100  0x0066 = 0x0003
0x007c = 0x5800  0x0000 = 0x0000  0x0000 = 0x0000  0x0000 = 0x0000
```

Note `0x0072 = 0x5678` and `0x0074 = 0x1234` — together the constant `0x12345678` across two
consecutive registers, which is a useful check that your entry decoding is aligned. Registers
`0x5c`, `0x66`, `0x7c` and `0x12a` each recur three times with different values, so this is an
ordered **write script**; replaying it as an unordered set will not work.

### Steady-state capture loop

For completeness, from USB captures of the vendor driver in normal use (observed):

```
TX 32 FDT down  [0c 01 + 6 × (80 xx) + uint16 timestamp]  → ACK … RX 32 event [02 00 ff 00 + 6 × u16]
TX 20 get image [01 00]                                   → ACK, RX b0 pack (TLS image)
TX 34 FDT up    [0e 01 + 6 × (80 xx)]                     → ACK … RX 34 event on lift [00 02 00 00 + 6 × u16]
   (optionally: TX 36 FDT manual [0d 01 + 6 × (80 xx)]    → ACK, RX 36 [00 01 ff 00 + 6 × u16]; TX 20 again)
```

The `0x80` before each threshold byte was constant across all 91 arms in one capture. The third header
byte is a flags field (seen: `2f`, `37`, `3d`, `3e`, `3f`), probably a mask of touched zones
(hypothesis). An `0x32` event beginning `80` rather than `02` comes back ~30 ms after an arm whose
thresholds were far off, and the driver immediately re-arms with fresh ones — "base invalid"
(hypothesis).

### TLS and the PSK — where this stops

(observed, except where marked)

- After `d0`, pack flag `0xb0` carries raw TLS records in both directions, and **the EC is the TLS
  client**: it sends the ClientHello and the *host* is the server.
- TLS 1.2, exactly one suite offered: `0x00ae` = `TLS_PSK_WITH_AES_128_CBC_SHA256`. PSK identity
  `Client_identity`.
- **The PSK is not upstream's zero key.** On this machine it is 32 random bytes the Windows driver
  generated at provisioning time, sealed on the host and written into the EC with `0xe0`. At each init
  the driver unseals it, hashes it and compares against the hash returned by `0xe4`. The sealed blob
  here is a DPAPI (`CryptProtectData`) blob, 332 bytes, written once in 2021 — despite strings in the
  driver that suggest SGX or an "IntelME pmk hash".
- Consequence for a Linux implementation: everything up to `d0` works without secrets, and **not one
  image can be read without either the host-side PSK or a destructive re-provision with `0xe0`**, which
  would break Windows Hello on the machine. No PSK material, sealed or otherwise, appears in this
  report.
- Images arrive as a single `b0` pack of **7749 bytes** carrying one TLS application-data record
  (`17 03 03 1e 40`, 7744 bytes).
- **Hypothesis, arithmetic only:** for AES-128-CBC with SHA-256, a 7744-byte record is a 16-byte
  explicit IV plus 7728 bytes of ciphertext, so the plaintext is between 7680 and 7695 bytes. 80 × 64
  samples packed 4-per-6-bytes is 7680 exactly, and 7680 + upstream's 8-byte header and 5-byte trailer
  is 7693, which also fits. Both are consistent; the record length alone cannot separate them, and
  nothing here has been measured against plaintext. Note also that upstream's 12-bit unpacking is
  transcribed for the 5110 and is **unverified** on this part.

### Two questions

1. **Has anyone seen an `ITE_EC` firmware string on another Goodix part?** Anything of the form
   `GF_ITE_EC_*` rather than `GF_ST411SEC_*`. What would be most useful is whether the empty-payload
   `0xe4` behaviour travels with the EC firmware family or is specific to this laptop's integration —
   and, given what it costs to test, we would rather hear it from a log than have anyone reproduce it.
2. **Has anyone unsealed a Windows-provisioned Goodix PSK before?** Here it lives in
   `C:\ProgramData\Goodix\Goodix_Cache.bin` as a DPAPI blob and recovering the plaintext needs the
   user- or machine-scoped DPAPI master key. If someone has already worked out whether these parts can
   be handled without that — for example whether re-provisioning with `0xe0` is cleanly reversible by
   the Windows driver — it would save a destructive experiment.

### How much this is worth

One device, one laptop, roughly one month of logs and four live runs, three of which ended with a dead
keyboard. The framing, the ACK convention, the two-transfer rule, the device identity and the init
sequence are measured. Everything marked hypothesis is not. Corrections welcome — particularly from
anyone with a second `GF_ITE_EC_*` part, since nothing here can distinguish "this family" from "this
laptop".

A parallel report goes to the libfprint tracker with the same device facts framed for a driver author:
**[PLACEHOLDER — libfprint issue URL once Draft B is posted]**.
All of the offline tooling behind this report — the protocol notes, the USBPcap reader and the
payload-rule enforcement that makes the `0xe4` frame unsendable — is at
<https://github.com/CWBudde/goodix-5120-linux>.

---
---

# Draft B — for the libfprint issue tracker

**Destination:** <https://gitlab.freedesktop.org/libfprint/libfprint/-/issues>. Check first whether an
issue for `27c6:5120` already exists and comment there instead of opening a second one.

**Before posting:** settle the `0x90` decision above; paste a real `lsusb -v` dump into the placeholder
(do not invent one); add the goodix-fp-dump link once Draft A is posted.

---

## Title

`27c6:5120` (Huawei MateBook `HVY-WXX9`): USB-attached ITE EC bridge — device facts, and a hardware
warning for anyone probing it

## Body

### Summary

This is a report, not a support request, and not a patch. `27c6:5120` as fitted to a Huawei MateBook
`HVY-WXX9` has no driver anywhere — `goodixmoc` targets the match-on-chip `27c6:58xx`/`6xxx` parts,
Huawei never shipped a TOD blob, and the Dell/Lenovo `libfprint-2-tod1-goodix` packages cover other
PIDs. `fprintd-list` reports "No devices available" on an otherwise complete stack.

Posting it for two reasons: **there is a way to probe this device that kills the laptop's internal
keyboard**, and a driver author should know that before touching it; and the plaintext half of the
vendor's initialisation is now known frame by frame, which is most of what a driver would need up to
the point where it hits a wall.

**The wall is the PSK**, and it is not upstream's zero key. Without it this part cannot produce an
image on Linux. That is stated up front because it determines whether any of the rest is worth a
maintainer's time.

### Hardware warning — read before probing this device

The device does not identify as a Goodix sensor MCU. It reports **`GF_ITE_EC_20063`**: an ITE embedded
controller bridging to the sensor. On this laptop **that same controller drives the internal keyboard
over i8042**.

**Sending `preset_psk_read` (`0xe4`) with an empty payload stops it.** The EC ACKs within a few
milliseconds, then never responds again, and the internal keyboard dies at the same instant. Observed
three times (2026-08-17, and twice on 2026-09-19); the third run sent that single frame and nothing else
after attaching, so no other command is involved. Recovery is a **cold power cycle** — full shutdown,
charger unplugged, power button held ~30 s. A warm reboot does not reset the EC.

What makes this a driver-author problem rather than a curiosity:

- **Linux observes nothing.** No USB disconnect, no i8042 or atkbd message, no ACPI SCI. The device
  stays enumerated. The kernel log cannot tell you which command did it. (observed)
- **The EC stops serving i8042 within tens of milliseconds** — twice a key *make* was delivered and its
  *break* never arrived. (observed)
- **Nothing in firmware can recover it.** On this machine the sensor's USB port
  (`\_SB.PCI0.GP17.XHC0.RHUB.PRT4`) carries `_ADR`, `_UPC` and `_PLD` and nothing else: no `_PRW`, no
  power resource, no `_DSM`. There is no ACPI method and no driver-reachable path that can drop power
  to the port or reset the sensor. The EC's watchdog resets the *system*, and is itself a service of
  the stuck firmware. (observed)
- **The opcode is not the hazard; the missing argument is.** The Windows driver sends `0xe4` with an
  8-byte argument in all 9 of its complete initialisations and is answered normally. *Why* the EC
  blocks on the empty form is a hypothesis — presumably its handler reads an argument that is not there
  and blocks after having queued the ACK. The same shape shows in `read_otp` (`0xa6`), whose empty form
  draws no reply at all. (observed; the mechanism is hypothesis)

So the general rule for EC-bridged parts: **classify opcodes by what they can do to the whole
controller, not by what they do to the sensor.** "Read-only" is the wrong safety axis when the silicon
is shared. Also relevant to anyone porting the existing 51x0 reverse-engineering work: upstream's
`driver_51x0.main()` flashes `GF_ST411SEC_APP_12117.bin` over IAP when the running firmware string does
not match — and on this device it never matches, so that path would fire. And the vendor driver
deliberately never sends `nop` to these parts ("not to send nop for ITE EC projects"); on this device
`nop` draws no reply at all in three live runs.

### Device

| | |
|---|---|
| USB ID | `27c6:5120`, `bcdDevice 2.00` |
| Machine | Huawei MateBook, DMI product `HVY-WXX9`; BIOS 1.08, EC firmware release 1.8 |
| OS during the runs | Ubuntu 26.04, kernel 7.0.0-29-generic |
| Firmware string (`0xa8`) | `GF_ITE_EC_20063` |
| Chip ID (`0x82`) | `0x2504` — vendor calls it "ChicagoHS", sensor type 12 |
| Sensor geometry | **80 × 64** per the vendor driver, not upstream's 80 × 88 |
| Transport | USB bulk. **Not SPI** — there is no `/dev/spidev*` on this machine, so `goodix-fp-dump`'s `run_5120_spi.py` path does not apply |
| Kernel driver bound | none, on either interface. No `/dev/ttyACM*`; the `driver` symlinks under `/sys/bus/usb/devices/1-4:1.{0,1}/` do not resolve |
| Access | free for userspace libusb, but root-only: an unprivileged open fails `LIBUSB_ERROR_ACCESS` |

Descriptor, abridged to the fields that matter (observed):

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

**Full `lsusb -v -d 27c6:5120`** (observed, 2026-09-20; run unprivileged, so the string descriptors are not read — that is the "Couldn't open device" line, not a device fault):

```
Bus 001 Device 003: ID 27c6:5120 Shenzhen Goodix Technology Co.,Ltd. Unknow device
Couldn't open device, some information will be missing
Negotiated speed: Full Speed (12Mbps)
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               2.00
  bDeviceClass            2 Communications
  bDeviceSubClass         1 Direct Line
  bDeviceProtocol         1 
  bMaxPacketSize0        64
  idVendor           0x27c6 Shenzhen Goodix Technology Co.,Ltd.
  idProduct          0x5120 Unknow device
  bcdDevice            2.00
  iManufacturer           1 
  iProduct                2 Unknow device
  iSerial                 0 
  bNumConfigurations      1
  Configuration Descriptor:
    bLength                 9
    bDescriptorType         2
    wTotalLength       0x0043
    bNumInterfaces          2
    bConfigurationValue     1
    iConfiguration          0 
    bmAttributes         0x60
      (Missing must-be-set bit!)
      Self Powered
      Remote Wakeup
    MaxPower              100mA
    Interface Descriptor:
      bLength                 9
      bDescriptorType         4
      bInterfaceNumber        0
      bAlternateSetting       0
      bNumEndpoints           1
      bInterfaceClass         2 Communications
      bInterfaceSubClass      1 Direct Line
      bInterfaceProtocol      1 
      iInterface              0 
      CDC Header:
        bcdCDC               1.10
      CDC Call Management:
        bmCapabilities       0x00
        bDataInterface          1
      CDC ACM:
        bmCapabilities       0x02
          line coding and serial state
      CDC Union:
        bMasterInterface        0
        bSlaveInterface         1 
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x82  EP 2 IN
        bmAttributes            3
          Transfer Type            Interrupt
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0008  1x 8 bytes
        bInterval              16
    Interface Descriptor:
      bLength                 9
      bDescriptorType         4
      bInterfaceNumber        1
      bAlternateSetting       0
      bNumEndpoints           2
      bInterfaceClass        10 CDC Data
      bInterfaceSubClass      0 [unknown]
      bInterfaceProtocol      0 
      iInterface              0 
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x01  EP 1 OUT
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval               0
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x83  EP 3 IN
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0040  1x 64 bytes
        bInterval               0
```

Three things in there are worth a driver author's attention:

- **It negotiates Full Speed, 12 Mbit/s** — not High Speed, despite `bcdUSB 2.00`. With 64-byte bulk packets that caps the link at roughly 1.2 MB/s in theory, so a 7749-byte image pack cannot cross the wire in less than about 6.5 ms, and in practice rather more. That bounds any imaging loop before anything in software does. (arithmetic, not measured — the capture used for the frame counts is no longer on disk)
- **`bmAttributes 0x60` is malformed.** Bit 7 is reserved and must always be set; this device reports Self Powered and Remote Wakeup without it, which is why `lsusb` prints "Missing must-be-set bit!". Harmless in practice, but it is a straightforward spec violation in the descriptor and a fair indication of how carefully the firmware was written.
- **Remote Wakeup is set**, which fits the driver log's "resume from S0 idle" transitions: the device is expected to wake the host, and a driver that suspends it should expect it back.

The device presents as **CDC ACM** — a USB serial port — but nothing about the payload is serial; the class is a wrapper. On this machine no kernel driver binds either interface and no `/dev/ttyACM*` appears, so libusb can claim interface 1 directly. Do not rely on that: `cdc_acm` binding is a plausible outcome on another kernel or with different udev rules, and a driver should be prepared to detach it.

The internal keyboard is a separate Linux device — `AT Translated Set 2 keyboard` on `isa0060/serio0`,
through `i8042`/`atkbd` — and that is precisely the point: it is a different host interface into the
same ITE part. The ACPI tables show three of them: the USB device, the keyboard controller (`PNP0303`,
`0x60`/`0x64`, IRQ 1) and the ACPI EC channel (`PNP0C09`, GPE 3). Nothing in ACPI names a fingerprint
reader at all.

### Protocol, as it stands

Framing is the Goodix 51x0 "wrapped" protocol, two nested layers, and it is **confirmed on this
device** — every pack and message checksum verifies across four live runs and four USB captures of the
vendor driver (382 decoded frames, 0 failures). (observed)

- pack `[flags:1][length:2 LE][checksum:1][payload:N]`, `checksum = sum(bytes[0:3]) & 0xff`
- message `[cmd:1][length:2 LE][payload:N][checksum:1]`, length = `len(payload) + 1`,
  `checksum = (0xaa - sum(bytes[0 : 2+length])) & 0xff`

Four behaviours differ from the published Python description of the family, and a driver has to handle
all four (all observed here):

1. **ACKs are a distinct `0xb0` message with payload `[original_cmd][status]`** — not the documented
   `cmd | 0x01` echo. Keep it apart from the pack-layer `0xb0` (TLS data): same value, different layer.
2. **Two transfers per command** — ACK first, then the data response as a separate transfer. A reader
   that reads once per command silently runs one transfer behind. `0xae` and `0xd0` are exceptions:
   they get no ACK at all.
3. **Unsolicited messages arrive**, because the vendor driver leaves the EC armed for finger detection
   when it goes idle and never disarms it. A machine rebooted from Windows meets an armed EC that
   reports the next touch as an `0x32` event to whoever reads the endpoint.
4. **Empty payloads are not benign** — see the warning above.

The vendor's initialisation is known frame by frame from the driver's own ETW debug channel: 18 inits
logged over a month, 9 of them complete, all 9 identical. In order, with payloads:
`96 [01 02]` → `a8 [00 00]` → `ae [55 + uint32 timestamp]` → `e4 [03 00 02 bb 00 00 00 00]` →
`a2 [01 14]` → `82 [00 00 00 04 00]` → `a6 [00 00]` → `a2 [01 14]` → `70 [14 00]` → `98 [8 bytes from
the OTP]` → `90 [224-byte config]` → `d0 [00 00]` → `d4 [00 00]` → `ae`, then FDT calibration and arming
with `32`. Every command carries a payload, even where it is only `00 00`. The full table, with reply
shapes, is in the companion report to `goodix-fp-dump` linked below.

The `0x90` config — the only frame a debug log cannot give you, since it truncates the payload — was
recovered statically from the vendor's Windows DLL: **224 bytes**, 232 bytes as a complete frame. It is
an ordered **write script**, not a register map — a 29-byte header, 48 `[register LE16][value LE16]`
entries, a 3-byte tail, with several registers recurring at different values, so it cannot be replayed
as an unordered set (structure is interpretation; the bytes and the boundary are not).
`sum(payload) & 0xff == 0xaa` pins the 224-byte length, and it is corroborated by 19 byte-identical
copies in the DLL, by matching the debug log's first 57 bytes in all nine complete inits, and by
re-encoding to the logged frame byte for byte.

**Provenance and basis for sharing this.** These bytes were obtained by static analysis of the vendor's
Windows driver on hardware I own, under the interoperability exception in Directive 2009/24/EC Art. 6
(§ 69e UrhG in Germany), for the sole purpose of making an independent Linux implementation work with
the device. They are a hardware register/value table rather than program logic, which on the *SAS
Institute* (C-406/10) reasoning is unlikely to be protected expression at all. Nothing of the driver's
code is reproduced here, and no per-device secret is included — the device PSK hash, the OTP and the
sealed key blob are all deliberately withheld. If a maintainer would rather this material were not
carried in your tracker, say so and I will remove it.

**The payload (224 bytes, hex):**

```
7011607100712c9d1cb918d100d100d100ba000180ca000400840015b3860000
c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1940000a8960000
b6980000009a000000d2000000d4000000d6000000d800000050000105d00000
00700000007200785674003412200010402a0182032200012024001400800001
005c000001560004205800030232000c02660003007c000058820080152a0108
005c008000540010016200040364001900660003007c0000582a0108005c0000
015200080054000001660003007c000058000000000000000000000000007815
```

The complete frame on the wire is 232 bytes: pack `a0 e4 00 84`, message `90 e1 00`, the 224 bytes
above, then the message checksum `8f`.

**Decoded as `[register LE16][value LE16]` entries** (interpretation, not fact — the byte sequence is
what is observed). Bytes 0..28 are a header that does not fit the entry pattern and is not decoded;
bytes 29..220 are 48 four-byte slots of which the last three are zero-filled, so **45 slots are
used**; bytes 221..223 are a 3-byte tail.

```
0x0086 = 0xc400  0x0088 = 0xba00  0x008a = 0xb200  0x008c = 0xaa00
0x008e = 0xc100  0x0090 = 0xbbbb  0x0092 = 0xb1b1  0x0094 = 0xa800
0x0096 = 0xb600  0x0098 = 0x0000  0x009a = 0x0000  0x00d2 = 0x0000
0x00d4 = 0x0000  0x00d6 = 0x0000  0x00d8 = 0x0000  0x0050 = 0x0501
0x00d0 = 0x0000  0x0070 = 0x0000  0x0072 = 0x5678  0x0074 = 0x1234
0x0020 = 0x4010  0x012a = 0x0382  0x0022 = 0x2001  0x0024 = 0x0014
0x0080 = 0x0001  0x005c = 0x0100  0x0056 = 0x2004  0x0058 = 0x0203
0x0032 = 0x020c  0x0066 = 0x0003  0x007c = 0x5800  0x0082 = 0x1580
0x012a = 0x0008  0x005c = 0x0080  0x0054 = 0x0110  0x0062 = 0x0304
0x0064 = 0x0019  0x0066 = 0x0003  0x007c = 0x5800  0x012a = 0x0008
0x005c = 0x0100  0x0052 = 0x0008  0x0054 = 0x0100  0x0066 = 0x0003
0x007c = 0x5800  0x0000 = 0x0000  0x0000 = 0x0000  0x0000 = 0x0000
```

Note `0x0072 = 0x5678` and `0x0074 = 0x1234` — together the constant `0x12345678` across two
consecutive registers, which is a useful check that your entry decoding is aligned. Registers
`0x5c`, `0x66`, `0x7c` and `0x12a` each recur three times with different values, so this is an
ordered **write script**; replaying it as an unordered set will not work.

### What would have to be true for libfprint to support this part

Not a proposal — an honest list of the gates, in the order they bite.

1. **A PSK.** After `d0` the EC becomes the TLS **client** and the host is the **server**: TLS 1.2,
   one suite offered, `0x00ae` = `TLS_PSK_WITH_AES_128_CBC_SHA256`, identity `Client_identity`. Images
   arrive only as TLS application data. On this machine the key is **32 random bytes generated by the
   Windows driver at provisioning**, sealed host-side with DPAPI and written into the EC — *not*
   upstream's zero key. A Linux driver therefore needs either that key off the Windows install, or to
   re-provision the EC with `0xe0`, which overwrites the device's PSK and breaks Windows Hello until
   Windows re-provisions. Until one of those is answered, **no image can be read**, and everything
   below is hypothetical. (observed)
2. **A TLS-PSK server in the host process.** Unusual shape: the peripheral is the client. Whatever TLS
   library a driver used would have to offer `PSK-AES128-CBC-SHA256` on the server side.
3. **Image decode confirmed against real plaintext.** 80 × 64 is from the vendor driver, not measured
   here, and upstream's 12-bit sample packing is transcribed for a different part in the family and
   unverified on this one. The one arithmetic hint available: the image record is 7744 bytes, which for
   AES-CBC/SHA-256 puts the plaintext between 7680 and 7695 bytes, and 80 × 64 packed 12-bit is 7680
   exactly. Consistent, not proof. (hypothesis)
4. **A finger-detect loop.** `32` (down) / `20` (get image) / `34` (up), with `36` for manual FDT; the
   arm payloads carry six per-zone thresholds that the driver recomputes from the previous readings
   (the recomputation is a hypothesis; the frame shapes are observed).
5. **A safety story for EC-bridged parts.** Whether libfprint would want a driver that can, through a
   malformed frame, take out the machine's keyboard until a cold power cycle is a maintainer question,
   not ours. If such a driver were ever written it would want the payload of every command fixed and
   enforced, rather than constructed.

### Still unknown

- The PSK, and whether the DPAPI blob can be unsealed at all without the machine's master key.
- Whether `0xe0` re-provisioning is cleanly reversible by the Windows driver (its strings suggest it
  generates and writes a PSK, but that has not been tested and testing it is destructive).
- Whether the empty-payload `0xe4` hazard is a property of this EC firmware family or of this laptop's
  integration. One device is one device.
- The real plaintext image layout, and therefore the geometry, verified rather than read off the vendor
  driver.
- What the 29-byte header of the `0x90` config means; the register semantics behind it; and `0x50`
  ("nav mode"), which appears in the vendor's log and in no capture.
- Whether any of this generalises to other `27c6:5120` units — this one is USB-attached, and the same
  PID exists SPI-wired elsewhere.

### Questions

1. Has any libfprint contributor met a Goodix part reporting an `GF_ITE_EC_*` firmware string rather
   than `GF_ST411SEC_*`? If the empty-payload `0xe4` behaviour is known from another machine, it would
   be far better to hear it than to have anyone reproduce it.
2. Has anyone unsealed a Windows-provisioned Goodix PSK (`Goodix_Cache.bin`) before, or established
   whether these devices survive being re-provisioned?

### Provenance

One device, one laptop, four live runs (three of which ended in a dead internal keyboard), four USB
captures of the Windows driver in normal operation, and about a month of that driver's debug log.
Statements above are marked observed or hypothesis; nothing is inferred silently. No PSK material, no
sealed blob, no OTP bytes and no capture files are included, here or anywhere this work is published.

A companion report with the full frame-by-frame protocol detail goes to the `goodix-fp-dump` project:
**[PLACEHOLDER — goodix-fp-dump issue URL once Draft A is posted]**.
All of the offline tooling behind this report — the protocol notes, the USBPcap reader and the
payload-rule enforcement that makes the `0xe4` frame unsendable — is at
<https://github.com/CWBudde/goodix-5120-linux>.

---
---

## Deliberately not in either draft

Recorded so the omissions are visible rather than accidental, per the never-publish rule in `PLAN.md`:

- The 32-byte PSK hash returned by `0xe4`. The drafts describe the reply's *shape* (type, length, a
  32-byte hash) and no bytes.
- Any byte of `C:\ProgramData\Goodix\Goodix_Cache.bin`, its DPAPI master-key GUID, and its size-and-date
  metadata beyond "332 bytes, written once in 2021". The well-known DPAPI *provider* GUID is not
  included either: it is a public Microsoft constant, but it is only needed to prove the claim, and the
  claim is stated plainly instead.
- OTP bytes, including the ASCII prefix the vendor log shows, and the 8 DAC values in the `0x98` frame,
  which the vendor's own log says are derived from the OTP.
- Any capture file, any frame from an image transfer, and anything derived from a fingerprint image.
- The 224 bytes of the `0x90` config and its decoded register-address list, pending the decision at the
  top of this file.
