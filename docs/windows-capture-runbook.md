# Windows capture runbook: the one capture that is still missing

Two USBPcap captures exist and both show **steady state**. The vendor driver's init has never been
seen on the wire. This runbook is now only about getting that one capture, plus three files worth
carrying back in the same session.

## What we already have, and why it was not enough

| file | what it was | frames on the device |
|---|---|---|
| `restart.pcapng` | `Restart-Service WbioSrvc` | **2** — one `0xae`, one reply |
| `dump.pcapng` | 43 finger captures | 382, all steady state |
| `Goodix-FingerprintProvider%4Debug.evtx` | driver debug log | 8 complete inits, the `0x90` config truncated |

(Counts from `./goodix-pcap -in restart.pcapng` and `-in dump.pcapng`.)

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

## Your capture settings were right — keep them

`goodix-pcap` found the device from its descriptor (bus 2, device 2) in both files, and every pack
and message checksum verified across all 384 frames. Same USBPcap interface, same three options
(*Capture from all devices connected*, *Capture from newly connected devices*, *Inject already
connected devices descriptors*). Nothing to change.

## The session: four things, one boot

External USB keyboard plugged in, as before.

### 1. The init capture — the point of the exercise

1. Start the capture on the same USBPcap interface.
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

In Wireshark, on the saved file, display filter:

```
usb.capdata[0] == a0 && usb.capdata[4] == 90
```

That is a plaintext pack (`a0`, 4-byte pack header) whose message opcode is `0x90` upload_config.
**Exactly one packet means success.** Zero means no init ran, and the file is not worth carrying back.

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
