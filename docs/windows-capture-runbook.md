# Windows capture runbook: what does the vendor driver send?

Everything the probe sends today was transcribed from upstream's `driver_51x0.py`, which targets other
silicon. Run 2 (2026-09-19) showed what guessing costs: `preset_psk_read` (`0xe4`) wedged the EC and
took the internal keyboard with it. PLAN.md Phase 4 gates any further live run on the command sequence
the **vendor driver** actually uses. This runbook gets that sequence: boot Windows, let the Huawei/Goodix
driver talk to `27c6:5120`, and record the USB traffic with USBPcap.

This is passive. The vendor driver does the talking; we only listen. Nothing from this repo runs on
Windows.

## What we want out of it

In order of importance:

1. **Driver initialization.** The first commands after the device appears: which opcodes, in what order,
   with what payloads, and whether `0xe4` shows up and in what context.
2. **Enrollment** and **verification** (Windows Hello). Probably encrypted after a TLS handshake (pack
   flag `0xb0`). Even so, the plaintext commands before the handshake and the handshake itself matter.
3. **Sleep/resume and shutdown.** How the driver quiesces the EC. This may explain why the EC wedges
   when the host just goes away.
4. **The driver package itself**, for the "Windows driver analysis" item in PLAN.md Phase 3.

## What you need

- **Windows on this machine**, with the fingerprint reader working under Windows Hello. If it doesn't
  work yet, install the fingerprint driver for `HVY-WXX9` from Huawei PC Manager or the Huawei support
  page.
- **Wireshark for Windows** (wireshark.org). In the installer, **tick the USBPcap component**. It isn't
  always selected by default. **Reboot** afterwards: USBPcap is a filter driver and only attaches to hubs
  at boot.
- Optional: **USBView** (from the Windows SDK/WDK "Debugging Tools") to see which root hub the reader is on.
- An **external USB keyboard**, just in case. The vendor driver should be safe, but it talks to the same
  EC that drives the internal keyboard.
- A USB stick or a shared exFAT/NTFS partition to carry the captures back to Linux.

## Before

1. Plug in the external keyboard.
2. Check the reader works: Settings → Accounts → Sign-in options → Fingerprint recognition (Windows Hello).
3. Note the device in Device Manager. It is usually under **Biometric devices**, sometimes under
   another category. Properties → Details → *Hardware Ids* should show `USB\VID_27C6&PID_5120`. Also note
   *Driver* → Driver Details (file names) and Driver Version.
4. **Find the USBPcap interface.** Start Wireshark. The interface list shows `USBPcap1`, `USBPcap2`, ….
   Click the gear icon next to each. The one whose device tree lists the Goodix device (`27c6:5120`, or
   "Goodix"/"FingerPrint") is yours. Note the interface name and the device's **address** shown there.
5. In that interface's options, enable:
   - **Capture from all devices connected** is simplest. Filtering to a single device is possible but
     easy to get wrong, and the filter is applied in Wireshark later anyway.
   - **Capture from newly connected devices**
   - **Inject already connected devices descriptors** (so Wireshark can decode the descriptors of a
     device that was attached before the capture started)
6. Make a folder for the captures, e.g. `C:\goodix-captures\`.

Use one capture file per scenario below. Stop the capture (red square) and **File → Save As**
(`.pcapng`) between scenarios. Start each scenario by writing down the time, so it can be matched to the
capture.

## Scenario 1: driver initialization (most important)

The driver loads at boot, before any capture can run. So re-trigger it:

1. Start the capture on the USBPcap interface.
2. Wait ~5 s (records background traffic).
3. Device Manager → the fingerprint device → right-click → **Disable device**. Wait ~5 s.
4. Right-click → **Enable device**. Wait ~15 s, until the device is idle.
5. Stop and save as `01-init-disable-enable.pcapng`.

Repeat with a service restart. This may bring up the TLS session without a USB re-enumeration:

1. Start the capture.
2. Run an **admin** PowerShell: `Restart-Service WbioSrvc -Force` (Windows Biometric Service). Wait ~15 s.
3. Stop and save as `02-init-wbiosrvc-restart.pcapng`.

If disable/enable doesn't produce a re-enumeration (no descriptor requests in the capture), try
**Uninstall device** (don't tick "delete the driver"), then **Action → Scan for hardware changes**.

## Scenario 2: enrollment

1. Start the capture.
2. Settings → Sign-in options → Fingerprint recognition → **Add a finger** (or set up, if none is
   enrolled). Complete the enrollment.
3. Stop and save as `03-enroll.pcapng`.

**This capture may contain fingerprint images.** See "Handling the files".

## Scenario 3: verification

1. Start the capture.
2. Lock with **Win+L**. The capture keeps running behind the lock screen.
3. Unlock with the finger. Do it three times, with one deliberate **wrong finger** attempt.
4. Stop and save as `04-verify.pcapng`.

## Scenario 4: sleep/resume (optional)

1. Start the capture.
2. Start → Power → **Sleep**. Wait ~30 s, then wake it up and unlock with the finger.
3. Stop and save as `05-sleep-resume.pcapng`.

Wireshark may lose the capture across sleep. If so, save whatever it has.

## Scenario 5: shutdown (optional)

Capturing the shutdown sequence needs `USBPcapCMD` writing straight to disk. Wireshark exits too early.
In an **admin** command prompt:

```bat
"C:\Program Files\USBPcap\USBPcapCMD.exe" -d \\.\USBPcap1 -A -o C:\goodix-captures\06-shutdown.pcap
```

(Replace `USBPcap1` with your interface.) Then shut down from the Start menu in another window. The file
may be truncated at the end, but it usually keeps most of the traffic.

## The driver package

In an **admin** PowerShell:

```powershell
pnputil /enum-drivers > C:\goodix-captures\drivers.txt
# Find the oemNN.inf whose "Original Name" / provider is Goodix or Huawei fingerprint, then:
pnputil /export-driver oemNN.inf C:\goodix-captures\driver
```

This copies the complete package (`.inf`, `.sys`/`.dll`, and any firmware images) out of the
DriverStore. Also save the driver version from Device Manager into a text file next to it.

Optional: `Get-PnpDevice -InstanceId 'USB\VID_27C6*' | Format-List *` and
`Get-PnpDeviceProperty -InstanceId '<the id>'` into a text file, for the device and its parent hub.

## Before booting back to Linux

- Shut down with a **full shutdown**, not Fast Startup: hold Shift while clicking **Shut down**, or run
  `shutdown /s /t 0` in a command prompt. With Fast Startup, Windows hibernates the kernel, and the
  EC/sensor may not be in a clean state for Linux.
- Copy `C:\goodix-captures\` to the USB stick or shared partition.

## Handling the files

- **Never commit captures or the driver package.** `.gitignore` covers `*.pcap`, `*.pcapng`, `/captures/`
  and `/windows-driver/`. Put them in `captures/` in the repo checkout, or outside it.
- Enrollment and verification captures may contain biometric data. Don't upload them anywhere, and
  don't paste raw payloads from them into issues or docs.
- The driver package is Huawei/Goodix proprietary code. Keep it local (`windows-driver/`) for analysis.

## Afterwards (back on Linux)

1. Check the captures open: `tshark -r captures/01-init-disable-enable.pcapng | head`.
2. Find the device's address from the descriptors (`usb.idVendor == 0x27c6`), then look at only its
   traffic:

   ```sh
   tshark -r captures/01-init-disable-enable.pcapng \
     -Y 'usb.device_address == N' \
     -T fields -e frame.number -e frame.time_relative -e usb.transfer_type \
     -e usb.endpoint_address -e usb.setup.bRequest -e usb.capdata
   ```

   Look at **all** transfer types, not only bulk. The reader is a CDC device (interface 0 with interrupt
   EP `0x82`, interface 1 with bulk `0x01`/`0x83`, see `docs/protocol.md`), and the driver may send CDC
   control requests (`SET_LINE_CODING`, `SET_CONTROL_LINE_STATE`) that the probe doesn't send.
3. Ask Claude to decode the traffic with `internal/proto` and to turn it into replay fixtures (one script
   per scenario, like `run1Script`), so the vendor sequence is tested offline.
4. Record the result in `docs/protocol.md` as observed, marked "vendor driver, Windows", with the driver
   version. Include: the init sequence, where `0xe4` appears (if it does), where TLS starts, and any
   `0xf0` (firmware write) traffic. If the driver updates firmware on load, write it down, but it stays
   compiled out on our side.
5. Check off "Windows USB capture" (and "Windows driver analysis", if done) in PLAN.md Phase 3.

## If something goes wrong

- **USBPcap interfaces missing in Wireshark:** USBPcap isn't installed or you didn't reboot. Re-run the
  Wireshark installer, tick USBPcap, reboot.
- **Only a few packets, no bulk traffic:** wrong USBPcap interface, or "Capture from all devices" was
  off. Check the other interfaces.
- **Internal keyboard stops under Windows:** don't keep poking. Save the capture (external keyboard),
  then cold power cycle as in `docs/bisect-runbook.md`: shut down, unplug the charger, hold power ~30 s.
  That capture is extremely valuable. Note exactly what you did just before.
