# Plan: next steps for `27c6:5120`

Written 2026-09-19. Read [`FINDINGS.md`](FINDINGS.md) first: the one live run (2026-08-17) wedged the
ITE embedded controller and killed the internal keyboard until a cold power cycle.

The phases are ordered by risk. Phases 1–3 never touch the device. Phase 4 cannot start until its
gate is met.

---

## Phase 1 — Offline code fixes (no hardware)

Goal: make the probe match what the device actually does, verified only against the replay transport.

- [x] **Two reads per command.** Each command yields an ACK and then a separate data response
      (`docs/protocol.md`, "two transfers per command"). Change `cmd/goodix-probe/main.go` to read
      the ACK, then read the data, with a bounded timeout on each read.
- [x] **Recognise `0xb0` ACKs.** An ACK is a message with `cmd = 0xb0` and payload
      `[original_command][status]`, not `cmd | 0x01`. Add a decoder to `internal/proto`, for example
      `DecodeAck(payload) (orig Opcode, status byte, err)`, and replace the `IsAck` check in the probe.
      Keep the pack-layer `FlagTLSData` (`0xb0`) separate.
- [x] **Handle the unsolicited `0x32` message.** The EC sends it on attach. Log it and skip it; don't
      count it as the reply to `nop`.
- [x] **Drain the IN endpoint.** Before closing, read until a timeout so no response is left queued.
      *Hypothesis:* the old probe left responses unread in the EC, and that may have added to the
      wedge. This is unverified; don't rely on it as a safety fix.
- [x] **Replay fixtures from the real capture.** Turn Run 1 (`docs/protocol.md`, "Observed
      exchanges") into a replay script, and fix the dry-run fixture builder (`main.go` ~L170), which
      still uses the `cmd | 0x01` ACK. Tests must pass against the real bytes.
- [x] **Clean up `read_otp` (`0xa6`).** It returned neither an ACK nor data. Leave it out of the default
      probe sequence until someone understands it.
- [x] Update `FINDINGS.md`. "One transfer behind" is then fixed in code, which is **not** a
      recommendation to run it. Also remove the stale NTFS/`git init` known issue: the repo is under
      git now.

Done when `go test ./...` and `go vet ./...` pass and `--dry-run` prints the corrected exchange.

---

## Phase 2 — Publish the findings (no hardware)

The findings are useful right now. Publishing them stops the next person from repeating the keyboard
incident.

- [ ] Open an issue or discussion at [goodix-fp-linux-dev/goodix-fp-dump][dump]: `5120` over USB
      (not SPI) on Huawei `HVY-WXX9`, identifies as `GF_ITE_EC_20063`, confirmed framing,
      `0xb0` ACK convention, ACK + data per command, the keyboard-wedge warning and the cold power
      cycle that recovers it.
- [ ] Comment on or open an issue at the [libfprint tracker][issues] with the same device facts, the
      `lsusb -v` descriptor and the warning.
- [ ] Optional: push this repo publicly and link it from both.
- [ ] Ask upstream whether anyone has seen an `ITE_EC` firmware string on other Goodix parts.

---

## Phase 3 — Passive research (no hardware writes)

Goal: learn the command sequence the EC actually expects instead of guessing it from the ST411SEC
flow.

- [ ] **ACPI tables.** `sudo acpidump > acpi.dat && acpixtract -a && iasl -d dsdt.dat ssdt*.dat`.
      Look for EC methods or devices that mention the fingerprint reader or USB port `1-4`, and for a
      power/reset method that could reset the sensor without a cold boot. Only read tables; don't call
      any methods.
- [ ] **EC identity.** Check `dmidecode`, `/sys/firmware/acpi/tables` and `ec_sys` (read-only,
      `write_support=0`) to identify the ITE chip model and EC firmware version.
- [x] **Windows driver analysis.** Get the Huawei fingerprint driver package for `HVY-WXX9`. Unpack
      it and look for the firmware name (`GF_ITE_EC_*`), command tables and any embedded firmware
      images. 2026-09-19: `gfusb.dll` 1.1.122.127, strings plus its ETW debug log, which records every
      frame of 8 inits. No firmware images; the driver skips firmware updates for EC projects. See
      `docs/protocol.md`, "Vendor driver, Windows".
- [x] **Windows USB capture** (2026-09-19: WbioSrvc restart plus a capture session, steady state only; the
      EC keeps TLS up, so no init was on the wire. The init sequence came from the driver log instead.
      Replay fixtures still to do.) (best source, if Windows can run on this machine, e.g. on a spare disk or
      a live Windows To Go install). Use USBPcap + Wireshark on `27c6:5120` during driver load,
      enrollment and verification. Convert the capture into replay fixtures, so the exact expected
      sequence is tested offline. Step by step: [`docs/windows-capture-runbook.md`](docs/windows-capture-runbook.md).
- [ ] Record everything in `docs/protocol.md` and mark each item as observed or hypothesis.

Done when the command sequence used by the vendor driver is known, or it is clear it can't be
obtained.

---

## Phase 3b — Bisect the wedge (live, user's decision)

On 2026-09-19 the user chose to run one diagnostic live run before a vendor capture exists. The
aim is to learn *which* step stops the keyboard: attach, `nop`, `0xa8` or `0xe4`. The journal
shows the EC failed silently, so only a key press after each step can tell (FINDINGS.md). Claude
builds and tests the tooling offline; the user runs it.

- [x] `goodix-probe --bisect`: baseline check, attach-only step, then one command per step with drain,
      a keyboard check, host counters, kernel-log markers and an fsync'd log. Tested against the
      replay with a fake keyboard.
- [x] Rehearse: `sudo ./goodix-probe --bisect --replay` (real keyboard, no USB). 2026-09-19, all passed.
- [x] Live run per [`docs/bisect-runbook.md`](docs/bisect-runbook.md), with an external keyboard attached.
      2026-09-19: attach, `nop` and `0xa8` passed; **`0xe4` wedged the EC** (ACK, then silence).
- [x] Record it as Run 2 in `docs/protocol.md`.
- [x] `0xe4` reclassified to `ClassStateChanging` and removed from `steps`; the probe now sends only
      `nop` and `0xa8`.
- [x] Live check of the fixed probe (Run 3, 2026-09-19 20:33): attach, `nop`, `0xa8` all passed.
- [x] Tooling to confirm `0xe4` alone: `--bisect --allow-e4 --steps e4`, the only path that can send
      `0xe4` (an exact `transport.Options.Allow` exception). Tested offline.
- [ ] Optional: confirm `0xe4` alone, live, per the runbook's "Confirming `0xe4` alone" section. Costs a
      cold power cycle, so run it right before booting Windows for the capture.

---

## Phase 4 — Live runs (only if the gate is met)

**Gate:** Phase 1 is complete, **and** Phase 3 produced a captured sequence from the vendor driver
that the planned commands follow exactly. Without a capture, don't run anything live. That's the
current recommendation.

If the gate is met:

- [ ] Plug in an external USB keyboard, or better, drive the machine over SSH from a second computer.
- [ ] Nothing else open or unsaved on the machine.
- [ ] Rehearse the recovery first: shut down fully, unplug the charger, hold the power button ~30 s.
      A warm reboot doesn't reset the EC.
- [ ] Send **one command per run**, only opcodes seen in the capture, in the captured order, with the
      default read-only ceiling. Drain responses before exiting.
- [ ] After each run, check that the internal keyboard still works
      (`evtest` on `AT Translated Set 2 keyboard`) and that `1-4` is still in
      `/sys/bus/usb/devices/`. Stop at the first sign of trouble.
- [ ] Append every run to `docs/protocol.md` as "Run N".

**Never, under any circumstances:** run upstream's `driver_51x0.main()` or any IAP/firmware-write path.
It would try to flash `GF_ST411SEC_APP_12117.bin` onto the ITE EC that also runs the keyboard.
`write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) stay out of the binary.

---

## Phase 5 — Driver work (far future, conditional)

Only if Phase 4 reliably gets image data without destabilising the EC:

- Tier 2: TLS-PSK session (`internal/tlspsk`) and image capture (`internal/image`).
- Then a libfprint driver or a TOD module, developed together with upstream.

---

## Recommended order

1. Phase 1 (code fixes against replay tests)
2. Phase 2 (publish)
3. Phase 3 (ACPI tables first, then the Windows driver/capture if feasible)
4. Decide on Phase 4 only once a vendor-driver capture exists

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[issues]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues
