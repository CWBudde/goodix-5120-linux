# Windows capture runbook: the one capture that is still missing

Two USBPcap captures exist and both show **steady state**. The vendor driver's init has never been
seen on the wire. This runbook is now only about getting that one capture, plus three files worth
carrying back in the same session.

## What we already have, and why it was not enough

| file | what it was | frames on the device |
|---|---|---|
| `restart.pcapng` | `Restart-Service WbioSrvc` | **2** — one `0xae`, one reply |
| `dump.pcapng` | 43 finger captures | 382, all steady state |
| `disable-enable.pcapng` | Disable/Enable attempt, 2026-09-19 22:24 | **0** — the sensor is not on that hub at all |
| `disable-enable2.pcapng` | Disable/Enable attempt, 2026-09-19 23:13 | **3** — the Disable only, over 22 s |
| `disable-enable3.pcapng` | Disable/Enable attempt, 2026-09-19 23:26 | **3** — the same Disable, over 85 s. The Enable produces nothing |
| `Goodix-FingerprintProvider%4Debug.evtx` | driver debug log | 8 complete inits, the `0x90` config truncated |

(Counts from `./goodix-pcap -in <file>`.)

The restart capture is the miss, and it shows exactly why it missed. Restarting `WbioSrvc` does not
reload the **UMDF driver host**. `gfusb.dll` stayed loaded, the EC still had its TLS session, so the
driver asked one question — `0xae` get_mcu_state, reply `isTlsConnected=1` — and went straight back
to steady state. No init. That is a property of the driver, not a mistake in the capture setup.

To see an init, the driver host has to reload **and** the EC has to lose its TLS session. Device
Manager → Disable → Enable does both, because it re-enumerates the USB device.

## What is missing, exactly

One frame: **`0x90` upload_config, 224 bytes.** The debug log truncates it, which makes it the only
outbound frame in the entire vendor init that nobody has the bytes for. It blocks a complete
vendor-init replay fixture, and with it PLAN.md Phase 4 step 5.

Secondary, from the same capture: the log-versus-wire comparison byte for byte, and the `d0` TLS
handshake as it actually appears on the wire.

## Attempts 3 and 4: the Disable is captured, the Enable is silent

Both found the sensor — bus 1, device 3, right hub, every checksum verifying — and both hold the
same three frames, the **Disable**:

| t | frame |
|---|---|
| +7.6 s | TX `96` enable_chip, payload `00 02` |
| +7.6 s | TX `ae` get MCU state |
| +7.6 s | RX 20-byte state |
| +9 s | the pending read is cancelled — the driver is unloading |
| after that | nothing |

Attempt 3 (`disable-enable2.pcapng`) stopped 13 s later, so "you stopped too early" was a fair
reading. Attempt 4 (`disable-enable3.pcapng`) ran **84.6 s**, **74.7 s of it after the driver
unloaded**, and the sensor still sent and received nothing — while a headset, a mouse and a disk on
the same hub kept transferring to the last second of the file. So the capture was alive and the
sensor was not.

Worth having anyway: the init's `96` carries `01 02` and this one carries `00 02`, so the driver does
have a shutdown command, which the debug log never showed (`docs/protocol.md`, "Disable device").
But the 224-byte `0x90` is still missing.

### Settle it with the debug log before capturing again

Two explanations are still open, and the `.evtx` separates them for free:

- **the Enable never ran an init** — the log will have no init at ~23:26;
- **it ran and USBPcap could not see it** — the log will have one, and then the capture approach is
  what has to change, not the clicking.

So the next trip starts with step 3 below, not with Wireshark. Copy the log out first and let it
decide.

### If the log says an init did run

Then the Disable/Enable path is not capturable this way, and the thing to try instead is the
stronger reload: Device Manager → **Uninstall device** — do *not* tick "delete the driver" — then
**Action → Scan for hardware changes**, with the capture running. That is a real PnP removal and
re-enumeration rather than a stack restart.

### If the log says no init ran

Then the Enable alone does not initialise the chip, and something has to ask for it. Lock the screen
(Win+L) and sign in with the finger, with the capture still running. That opens a WinBio session,
which is the one thing in these captures that has never been tried right after an Enable.

## Pick the interface first — the USBPcap number is not stable

This is what `disable-enable.pcapng` (attempt 2) missed on, and it is the one thing this runbook got
wrong. The options were right; **the interface was not the one the sensor is on.** Attempt 3 found it
on bus 1 — so the number does move, and it is worth one minute to confirm each time.

The file holds 18 transfers, all stamped 22:24:52.538 — the descriptor sweep USBPcap injects when it
starts, and then nothing. The three devices it enumerated are `05c8:03e6` (the camera),
`8087:0029` (the Bluetooth radio) and `04e8:4001`. No `27c6:5120`, no bulk transfer of any kind.
`goodix-pcap` says so outright:

```
goodix-pcap: no 27c6:5120 device descriptor in the capture; run with -devices to see
what is here, then pass -bus and -device
```

`-devices` is the whole diagnosis in one command — it lists every address in the file with its
vid:pid, its transfer counts and the span it was active over:

```
$ ./goodix-pcap -in disable-enable3.pcapng -devices
15 device addresses, 6492 USB transfers, over 84.581s from 2026-09-19 23:25:14.831 CEST

  address             id          transfers    bulk      first       last
  bus 1 device 13     046d:c093         2874       0     0.000s    84.581s
  bus 1 device 3      27c6:5120           14       8     0.000s     9.849s  <- the sensor
  bus 1 device 9      2537:1081          390     384     0.000s    84.393s
  ...
```

Two things fall out of that listing without any further work: whether the sensor is on this hub at
all, and — by comparing its last transfer against everyone else's — whether a silence is the sensor's
or the capture's. Above, the sensor stops at 9.849 s while two other devices transfer to the last
second, so the capture was alive and the sensor was not.

Both earlier captures were also taken on `\\.\USBPcap2`, and both found the sensor there — next to a
docking station (`2109`/`0451` hubs, a Logitech receiver, a USB disk), with no camera in sight. So
`USBPcap2` was a different root hub on that boot. **USBPcap numbers the filter devices per boot and
per hub topology; plugging or unplugging the dock renumbers them.** This laptop has two XHCI
controllers (`XHC0` and `XHC1` in ACPI — `docs/acpi.md`); the camera and the Bluetooth radio hang off
one, the fingerprint sensor off the other. An interface that shows you the camera is the wrong one.

Identifying it takes about a minute, and does not depend on Wireshark's UI:

1. For each `\\.\USBPcapN` in the list, start a capture, wait two seconds, stop, save as `probeN.pcapng`.
   The injected descriptor sweep alone is enough — no need to touch anything.
2. Back on Linux, `./goodix-pcap -in probeN.pcapng -devices`. The wrong hub lists devices with no
   `27c6:5120` among them; the right one marks the sensor. Or, without leaving Windows, filter on
   `usb.idVendor == 0x27c6`.

Keep the three options exactly as they were: *Capture from all devices connected*, *Capture from
newly connected devices*, *Inject already connected devices descriptors*. The third is what makes
the two-second probe work.

If you would rather not do two trips: select **every** `USBPcapN` interface in one Wireshark capture.
`goodix-pcap` finds the device by its descriptor, not by a hard-coded address, so a multi-interface
file is fine to hand it.

Everything else about the earlier captures was right — the device was found from its descriptor
(bus 2, device 2) and every pack and message checksum verified across all 384 frames.

## The device number changes when it comes back

An Uninstall and rescan — and in principle a Disable and Enable — brings the sensor back under a
**new USB device number**, in the middle of the same capture. `goodix-pcap` handles that: it finds
every address the `27c6:5120` descriptor appears at and decodes all of them together, in capture
order, saying so when there is more than one — illustration, no such capture exists yet:

```
found 27c6:5120 at 2 addresses — it re-enumerated during the capture:
  bus 1 device 3     14 transfers (8 bulk), 0.000s .. 9.849s
  bus 1 device 22    61 transfers (55 bulk), 12.104s .. 13.960s
  all of them are decoded together below, in capture order
```

Before this, the tool took the **first** address only. A capture of the Uninstall-and-rescan path
would have shown the pre-removal traffic, reported the init as absent, and looked exactly like
attempts 3 and 4 — the same wrong conclusion for a third time, from a capture that actually held the
answer.

The one case it cannot resolve by itself is a re-enumeration whose descriptor exchange was not
captured, because then nothing in the file says the new address is the same device. It reports that
as a note — bulk traffic appearing at an unidentified address after the sensor fell silent — and
`-devices` plus `-bus`/`-device` decodes it by hand.

## The session: four things, one boot

External USB keyboard plugged in, as before.

### 1. The init capture — the point of the exercise

1. Start the capture on the USBPcap interface you identified above — not "the same one as last
   time".
2. Wait ~5 s.
3. Device Manager → **Biometric devices** → the Goodix device → right-click → **Disable device**.
   Confirm. Wait ~5 s.
4. Right-click → **Enable device**. Wait ~20 s, until it is idle.
5. Touch the sensor once, so the file also ends in a known steady state.
6. Stop the capture, **File → Save As** → `01-init-disable-enable.pcapng`.

Check it before moving on — see below.

### 2. The driver package

There is no copy of `gfusb.dll` on the Linux side, and the PSK-sealing question (PLAN.md Phase 3) is
static analysis of that DLL. In an **admin** PowerShell:

```powershell
pnputil /enum-drivers > C:\goodix-captures\drivers.txt
# find the oemNN.inf whose provider is Goodix, then:
pnputil /export-driver oemNN.inf C:\goodix-captures\driver
```

### 3. The debug log

`C:\Windows\System32\winevt\Logs\Goodix-FingerprintProvider%4Debug.evtx` — copy it again. It is a
20 MB ring buffer, and the Disable/Enable init will be its newest entry. That is what makes the
log-versus-wire comparison possible.

### 4. The sealed PSK blob

`C:\ProgramData\Goodix\Goodix_Cache.bin`, 332 bytes. Its first 20 bytes settle the sealing question
on the spot: a DPAPI blob starts with
`01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb`. Anything else points at TPM/SGX.
**Never commit it and never publish it** — `*.bin` is gitignored, and PLAN.md lists the sealed blob
as never-publish.

## Check the capture worked, before you shut down

In Wireshark, on the saved file. First, is the sensor even on this hub:

```
usb.idVendor == 0x27c6
```

Zero packets means the wrong interface again — nothing else in the file matters. Then, the frame
this whole trip is for:

```
usb.capdata[0] == a0 && usb.capdata[4] == 90
```

That is a plaintext pack (`a0`, 4-byte pack header) whose message opcode is `0x90` upload_config.
**Exactly one packet means success.** Zero means no init ran, and the file is not worth carrying back.

If it is zero, this says which half you caught:

```
usb.capdata[0] == a0 && usb.capdata[4] == 96
```

Byte 7 of that packet is `01` for an init and `00` for a shutdown. Only the Disable in the file means
keep capturing and click Enable again.

Quicker smoke test: `usb.capdata[0] == a0` should give a few dozen packets, not 2. If Wireshark
rejects the slice syntax, just compare the packet count against `restart.pcapng` — an init is
visibly bigger than two frames, and a re-enumeration shows up as a burst of descriptor requests.

**If no init ran:** Device Manager → **Uninstall device** — do *not* tick "delete the driver" — then
**Action → Scan for hardware changes**, with the capture still running. That forces the reload.

## Back on Linux

1. **Full shutdown, not Fast Startup:** hold Shift while clicking *Shut down*, or `shutdown /s /t 0`.
   With Fast Startup, Windows hibernates the kernel and the EC is not in a clean state for Linux.
2. Captures to `captures/` in the checkout, driver package to `windows-driver/` — both gitignored —
   or keep them outside the repo.
3. Acceptance check:

   ```sh
   ./goodix-pcap -in captures/01-init-disable-enable.pcapng
   ```

   Expect the vendor init in the TX list: `96`, `a8`, `ae`, `e4`, `a2` ×2, `82`, `a6`, `70`, `98`,
   **`90` with 224 bytes**, `d0`, `d4`, then the FDT calibration and arming. The tool refuses to
   print `0xe4` and `0xa6` payloads at all.

   One thing that may go wrong on our side, not yours: `internal/capture` treats each bulk transfer
   as one whole pack and does not reassemble. The `0x90` frame is 232 bytes, the first outbound frame
   longer than the 64-byte OUT transfers seen so far. If Windows split it, the summary will report
   failed decodes around it. That is a tool fix here, not a bad capture — the bytes are in the file
   either way. (The 7749-byte inbound TLS packs do arrive as single transfers, so this probably
   won't happen.)
4. The `0x90` bytes then replace the synthetic config in the vendor-init fixture
   (`cmd/goodix-probe/fixtures_test.go`), and the result goes into `docs/protocol.md` as observed,
   with the driver version.
5. Tick **"Capture a real init on the wire"** in PLAN.md Phase 3.

## Scenarios that are no longer needed

- **Enrollment and verification.** `dump.pcapng` already covers verification (43 image captures), and
  the images are TLS ciphertext that is unreadable without the PSK. An enrollment capture would add
  biometric data and no protocol.
- **Sleep/resume and shutdown.** These existed to explain the wedge. The wedge is explained: an
  `0xe4` with an empty payload, confirmed in isolation by Run 4 (`docs/protocol.md`). That the driver
  sends nothing on idle or D0Exit, and leaves the EC armed in FDT-down mode with TLS up, is already
  established from the log.

## If the internal keyboard stops under Windows

Don't keep poking. Save the capture using the external keyboard, then cold power cycle as in
`docs/bisect-runbook.md`: shut down, unplug the charger, hold the power button ~30 s. That capture
would be extremely valuable — note exactly what you did just before.
