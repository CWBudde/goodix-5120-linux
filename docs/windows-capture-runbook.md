# Windows capture runbook: the one capture that is still missing

The vendor driver's init has never been seen on the wire. This runbook is about getting that one
capture.

**Updated 2026-09-20, and the diagnosis changed.** The Windows partition was read offline and the
debug log now says what the captures could not: the Disable/Enable procedure **worked every time**,
and two of the three attempts contain a complete init that USBPcap simply did not record. USBPcap
does not follow the device across a PnP re-enumeration. So the thing to change is the capture method,
not the clicking — and the three other files this runbook used to ask for have all been collected.

## What we already have, and why it was not enough

| file | what it was | frames on the device |
|---|---|---|
| `restart.pcapng` | `Restart-Service WbioSrvc` | **2** — one `0xae`, one reply |
| `dump.pcapng` | 43 finger captures | 382, all steady state |
| `disable-enable.pcapng` | Disable/Enable attempt, 2026-09-19 22:24 | **0** — the sensor is not on that hub at all |
| `disable-enable2.pcapng` | Disable/Enable attempt, 2026-09-19 23:13 | **3** — the Disable only. A complete init ran at 23:13:23, inside the window, uncaptured |
| `disable-enable3.pcapng` | Disable/Enable attempt, 2026-09-19 23:26 | **3** — the same Disable. A complete init ran at 23:25:41, 26.6 s in, uncaptured |
| `Goodix-FingerprintProvider%4Debug.evtx` | driver debug log | 18 inits, **9 complete**; the `0x90` config truncated to 57 of 224 bytes |

(Counts from `./goodix-pcap -in <file>`; init times from the log, read 2026-09-20.)

The restart capture is the miss, and it shows exactly why it missed. Restarting `WbioSrvc` does not
reload the **UMDF driver host**. `gfusb.dll` stayed loaded, the EC still had its TLS session, so the
driver asked one question — `0xae` get_mcu_state, reply `isTlsConnected=1` — and went straight back
to steady state. No init. That is a property of the driver, not a mistake in the capture setup.

To see an init, the driver host has to reload **and** the EC has to lose its TLS session. Device
Manager → Disable → Enable does both, because it re-enumerates the USB device.

## What is missing, exactly

One frame used to be missing: **`0x90` upload_config, 224 bytes** — the only outbound frame in the
entire vendor init that nobody had the bytes for, blocking a complete vendor-init replay fixture and
with it PLAN.md Phase 4 step 5.

**Recovered 2026-09-20 — this is no longer missing.** The driver truncates its own hex dump at 64
bytes of the pack, so the log yields only 57 of the 224 payload bytes and never will yield more
(verified at raw EVTX record level). The full 224 bytes were instead extracted statically from
`gfusb.dll`, which holds the blob 19 times over, byte-identical; its first 57 bytes match the log and
its checksum pins the boundary. See `docs/protocol.md`, "The 224-byte `0x90` config — recovered".

So **this capture is no longer a blocker** — it is now corroboration: the log-versus-wire comparison
byte for byte, and the `d0` handshake as it appears on the wire. Worth getting, no longer urgent.

## Attempts 3 and 4: the Disable is captured, the Enable is not

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

### Settled 2026-09-20: the init ran, USBPcap missed it

The debug log answers it. Both properly aimed attempts contain a **complete** init:

| capture | window | complete init inside it |
|---|---|---|
| `disable-enable2.pcapng` | 23:13:09.726 + 22.295 s | 23:13:23.144 |
| `disable-enable3.pcapng` | 23:25:14.831 + 84.581 s | 23:25:41.462 |

In attempt 4 the sensor's last captured transfer is 23:25:24.680, the init starts **16.8 s later**,
and neither it nor any new device address appears anywhere in the file. The clicking was right all
three times. **USBPcap does not follow the device across the PnP re-enumeration** the Enable causes.

Two consequences, and the second one reverses earlier advice in this file:

- A full init **requires** a re-enumeration. The driver short-circuits any init that is merely a
  resume, whatever the MCU reports — see "What triggers a full init" in `docs/protocol.md`. So there
  is no gentler trigger to fall back on: no Win+L fingerprint sign-in, no service restart.
- **Uninstall device + Scan for hardware changes is now a bad suggestion.** It is a *stronger* PnP
  removal, so it fails the same way, harder. Do not use it.

### What to try instead

Give USBPcap no stale device object to lose track of, and do not bet on one interface:

1. Device Manager → **Disable device** *first*, before Wireshark is anywhere near it. Wait ~5 s.
2. **Now** start the capture, with **every** `\\.\USBPcapN` interface selected at once, and confirm
   *Capture from newly connected devices* is ticked (along with the other two options).
3. Wait ~5 s, then **Enable device**. The sensor is now a genuinely new arrival rather than one
   USBPcap already holds a removed object for.
4. Wait ~20 s, touch the sensor once, stop, save.

If that still comes back with three frames, the next thing to try is a capture started before a
**full shutdown and cold boot** (Shift + *Shut down*, not Fast Startup) — the first init after boot is
also a `DriverState:Install` — though a boot-time capture needs USBPcap running as a service, which
is a bigger change than it sounds.

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

## The session: one thing, not four

External USB keyboard plugged in, as before.

**Only the capture is still outstanding.** The other three files this runbook used to ask for were
collected on 2026-09-20 by mounting the Windows partition read-only from Linux, which needs no
Windows session at all — see "Already collected" below.

### The init capture — the point of the exercise

Follow "What to try instead" above: **Disable first, then start the capture on every interface, then
Enable.** Then:

1. Wait ~20 s, until it is idle.
2. Touch the sensor once, so the file also ends in a known steady state.
3. Stop the capture, **File → Save As** → `01-init-disable-enable.pcapng`.

Check it before shutting down — see below. Copy the debug log out again in the same session too: it
is a ring buffer, and it is what tells you whether the init you were trying to catch actually ran.

## Already collected (2026-09-20) — no Windows session needed

All three came off the Windows partition mounted **read-only** from Linux. No Windows binary was run,
nothing was written to the partition, and none of the files enters the repository.

```sh
sudo mkdir -p /mnt/Windows && sudo mount -t ntfs3 -o ro /dev/nvme0n1p3 /mnt/Windows
```

Read-only matters: if the last Windows session ended with Fast Startup or hibernation the volume is
dirty, and a read-write mount of a hibernated NTFS volume is how a Windows install is lost.

**Copy with `cat`, not `cp`.** `cp` from an `ntfs3` mount uses `copy_file_range()`, which that driver
mishandles: it silently produces a file of the **correct size filled with zeros**. Eight of the nine
driver-package files came across that way on the first attempt, and a zero-filled DLL searches clean,
which is exactly how a false negative gets recorded as a finding. Copy with `cat src > dst` and verify:

```sh
cat /mnt/Windows/path/to/file > dest/file
md5sum /mnt/Windows/path/to/file dest/file   # must match
```

(Both `.evtx` copies were checked with `cmp` against the source and are byte-identical, so every
finding drawn from the debug log stands.)

- **The driver package.** `Windows/System32/DriverStore/FileRepository/gfusb.inf_amd64_4652ced462eef64a`
  → `windows-driver/` (gitignored). This is what `pnputil /export-driver` was only ever a way of
  reaching. It holds `gfusb.dll`, `EngineAdapter.dll`, `AlgoChicago.dll`, `AlgoMilan.dll`,
  `GoodixEventLog.dll`, `SessionService.exe` and `gfusb.inf`.
- **The debug log.** `Windows/System32/winevt/Logs/Goodix-FingerprintProvider%4Debug.evtx` →
  `captures/` (gitignored). Still worth re-copying after every capture attempt.
- **The sealed PSK blob.** `ProgramData/Goodix/Goodix_Cache.bin`, 332 bytes. **Answer: DPAPI**, not
  TPM/SGX — it begins `01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb`, the DPAPI
  provider GUID. **Never commit it and never publish it** — `*.bin` is gitignored, and PLAN.md lists
  the sealed blob as never-publish.

There is no EVTX tooling on this machine, so the log is read with a small record scanner rather than
`strings -el`, which cannot date a record. See `docs/protocol.md`, "The Windows partition, read
offline".

## Check the capture worked, before you shut down

In Wireshark, on the saved file. First, is the sensor even on this hub:

```
usb.idVendor == 0x27c6
```

Zero packets means the wrong interface again — nothing else in the file matters. Then the frame that
tells you an init ran (its bytes are known now, so this is a success check, not the prize):

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

**If no init ran:** do *not* reach for Uninstall device + Scan for hardware changes. That is more
re-enumeration, which is the thing USBPcap cannot follow, and it is why this file used to recommend
it. Copy the debug log out instead and check whether an init ran at all — if one did and the capture
missed it again, the capture method is still the problem, not the trigger.

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
