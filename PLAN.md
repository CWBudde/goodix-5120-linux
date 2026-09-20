# Plan: next steps for `27c6:5120`

Written 2026-09-19; refactored 2026-09-20. Read [`FINDINGS.md`](FINDINGS.md) first: the first live run
(2026-08-17) wedged the ITE embedded controller and killed the internal keyboard until a cold power cycle.
**The one part bridges the sensor and the keyboard**, so every live step is one command per run,
`--bisect`, external keyboard attached, and run by the repository owner — never by Claude, never
unattended. Never run upstream `driver_51x0.main()` or any IAP / firmware-write path; `write_firmware`
(`0xf0`) and `preset_psk_write` (`0xe0`) stay out of the default binary.

**This file is the plan, not the record.** Findings live in [`docs/protocol.md`](docs/protocol.md) (wire
protocol and every run), [`FINDINGS.md`](FINDINGS.md), [`docs/acpi.md`](docs/acpi.md),
[`docs/dpapi-runbook.md`](docs/dpapi-runbook.md), [`docs/bisect-runbook.md`](docs/bisect-runbook.md) and
[`docs/windows-capture-runbook.md`](docs/windows-capture-runbook.md). Append observations there, not here.

---

## Where we stand (2026-09-20)

The offline groundwork is complete. Everything open now is either an owner decision (publish) or
live-hardware bring-up.

- **Protocol known end to end up to `d0`.** Framing, the `0xb0` ACK convention and two-transfers-per-command
  are confirmed against hardware; the vendor's 14-frame init — including the 224-byte `0x90` config — is in
  the repo, so every outbound byte the vendor sends up to `d0` is reproduced.
- **Device identified:** an ITE EC (`GF_ITE_EC_20063`) in front of a Goodix sensor, chip ID `0x2504`,
  80 × 64. Treated as an "EC project": no `nop`, no firmware update, ever.
- **The wedge is understood and defused:** `0xe4` sent without its 8-byte argument. The transport can no
  longer build that frame, and all six safe init frames (`a8 ae e4 a2 82 a6`) run live with no ill effect.
- **PSK recovered and wired in.** `goodix-dpapi -goodix` unseals the 32-byte device PSK from
  `Goodix_Cache.bin` offline; `internal/tlspsk` consumes it via `LoadPSK` / `ParsePSKHex`.
- **TLS-PSK path validated offline.** `PSK-AES128-CBC-SHA256` (`0x00ae`) is confirmed available in the
  openssl the scaffold drives and negotiates at the default security level; `TestNegotiatesDeviceSuite`
  pins it.
- **Image decode verified in code.** `internal/image` implements upstream's irregular 6-byte / 4-sample
  12-bit layout; 80 × 64 = 5120 samples = 7680 plaintext bytes exactly.

**Two hard unknowns remain, and both need the device:** whether the EC accepts our recovered PSK (the TLS
wall), and the exact `d0` record framing and image plaintext length. The user has some hardware access, so
these are now schedulable — under the keyboard-safe procedure.

## Completed phases (detail is in the docs, not here)

| Phase | Result | Where |
|---|---|---|
| 1 — offline code fixes | done 2026-09-19 | `CLAUDE.md`, `docs/protocol.md` |
| 3 — passive research (driver log, USB captures, ACPI, `0x90`, DPAPI seal) | done | `docs/protocol.md`, `docs/acpi.md`, `docs/windows-capture-runbook.md` |
| 3b — bisect the wedge (Runs 2–4) | done 2026-09-19 | `docs/protocol.md`, `docs/bisect-runbook.md` |
| 3c — align code with the vendor sequence | done 2026-09-19 | `CLAUDE.md`, `cmd/goodix-probe/vendor.go` |
| 4 — live plaintext runs, steps 1–4 (Runs 5–10) | done 2026-09-20 | `docs/protocol.md` |
| 5 offline — PSK unseal + wire, TLS suite, image decode | done 2026-09-20 | `docs/dpapi-runbook.md`, `docs/protocol.md` |

---

## Phase 2 — Publish the findings (owner decision, no hardware) — open

Both write-ups are drafted and postable as-is in [`docs/upstream-report.md`](docs/upstream-report.md);
nothing has been posted. Posting is the owner's call, not a technical blocker.

- [ ] Work that file's **CHECK BEFORE POSTING** list. The mechanical half is verified; items **1, 2, 3, 7**
      remain and are all owner decisions (notably which identity — the company `MeKo-Christian` gh account
      vs. the `CWBudde` repo — the posts go out under).
- [ ] Post Draft A at [goodix-fp-dump][dump] and Draft B at the [libfprint tracker][issues]. Key content:
      `5120` over USB on Huawei `HVY-WXX9`, the framing / ACK corrections, and the warning that **`0xe4`
      without its payload wedges the EC and the keyboard**, with the cold power cycle that recovers it.
- [ ] Fill the two cross-link placeholders once the first post has a URL.

This also opens the Phase 6 collaboration with upstream, so it is worth doing before the driver work.

**Never publish:** the PSK, its hash from the `0xe4` reply, the recovered plaintext, `Goodix_Cache.bin`,
the DPAPI master-key GUID, OTP bytes, the OTP-derived `0x98` DAC values, or any capture.

---

## Phase 5 — Bring the sensor up (live hardware, owner-driven)

Gated on the keyboard-safe procedure in [`docs/bisect-runbook.md`](docs/bisect-runbook.md): one command
per run, `--bisect`, external keyboard attached, owner runs it. Each step is a small addition to
`cmd/goodix-probe`, gated behind an explicit `--allow-*` flag that mirrors `--allow-e4` / `--allow-a2`.

- [ ] **5a — Finish the init: `70`, `98`, `90`, then `d0`.** Promote one config frame per run, checking the
      keyboard after each; `90` (the 224-byte config) stays out of `steps` until deliberately promoted.
      These are `ClassStateChanging` with payload rules already in `vendor.go`. Goal: reach the `d0`
      TLS-start with the keyboard alive.
- [ ] **5b — TLS-PSK handshake against the device. (The decision point for the whole project.)** Add a
      session orchestrator wiring `internal/transport` ⇄ `internal/tlspsk` ⇄ the EC: the socket is
      ciphertext to and from the device, the pipes are plaintext. Feed `Config.PSK` from the recovered key
      (`tlspsk.LoadPSK captures/goodix-psk.bin`). **This is where the PSK wall is tested.** If the EC rejects
      it, take the fallbacks below before any more driver work.
- [ ] **5c — Capture and decode one real frame.** After the handshake, read the image records, strip the
      8-byte header / 5-byte trailer, run `internal/image.Decode12BitRaw`, and write a PGM into gitignored
      `captures/`. Confirms the 12-bit packing and the exact plaintext length (7680 vs ~7695) on hardware.
- [ ] **5d — Finger-detection (FDT) loop.** Implement the `32` / `20` / `34` sequence for finger-down / up,
      so a capture is triggered by touch rather than by hand.

**If the recovered PSK is rejected in 5b**, in order of preference:
1. Re-audit the unseal (secondary entropy, master key) — 5b is the first real test of the recovered key.
2. Read the PSK or entropy from a running Windows driver (`psk_simulation_switch`,
   `Local_test_original_psk`); local analysis only.
3. Provision our own PSK with `0xe0` — **destructive**: it overwrites the EC's PSK and breaks Windows Hello
   until Windows re-provisions. Last resort, behind an explicit build tag, and only after confirming Windows
   re-provisions cleanly. This is also the *only* path on a **Linux-only** machine, which has no
   Windows-sealed key to unseal (see Phase 6).

---

## Phase 6 — The real driver

**Goal:** working fingerprint authentication on this laptop through `fprintd` / PAM.

**Two layers, and they are not the same deliverable:**

1. **Go reference driver (this repo — safe, replayable).** Grow the probe into a full
   init → TLS → capture → FDT pipeline behind the live gate, keeping the replay transport and the class
   ceiling intact. This nails the protocol against hardware and stays the reference and test bed. It is
   *not* the shippable driver: matching, enrollment and PAM are libfprint's job, not something to
   re-implement in Go for biometrics.
2. **libfprint driver (C, upstream).** `fprintd` on top of libfprint is the only realistic path to
   enrollment, minutiae matching (libfprint's bundled NBIS) and PAM. Contribute a `goodix5120` driver
   modelled on the existing Goodix drivers and the community `goodixtls` work for the TLS 5xx parts. A
   libfprint out-of-tree **TOD** module is the fallback only if upstream declines the driver.

**Decide early — the PSK-provisioning problem.** A shipped driver needs the device's TLS PSK, and there is
no portable way to get it:
- **Dual-boot** machines can unseal it from Windows with `goodix-dpapi`, but that is host-specific and not
  something upstream libfprint can ship.
- **Linux-only** machines have no sealed key at all, so the driver must *provision* one with `0xe0` — the
  destructive Phase 5 option-3 path. Owning provisioning means owning the `0xe0` write path, which reverses
  this repo's "no destructive opcodes in the default build" stance. That reversal is a deliberate decision
  to make with upstream, not a default — and it must first be shown that Windows Hello (or a re-run of the
  Linux provisioning) recovers the device afterward.

**Build order:** Phase 5 a → d first (no driver work is meaningful until a real frame decodes), then the Go
pipeline end to end, then the libfprint port — developed with upstream off the back of the Phase 2 reports.

---

## Recommended order

1. **Phase 2** — owner posts the two drafts; this also opens the Phase 6 upstream collaboration.
2. **Phase 5a → 5b** — reach `d0`, then test the recovered PSK against the device. 5b decides the project.
3. **Phase 5c → 5d** — one real frame, then the FDT loop.
4. **Phase 6** — Go reference pipeline, then the libfprint driver (PSK-provisioning decision alongside).

**Dropped as no longer useful:** the standalone "capture a real init on the wire" task (old Phase 3).
USBPcap cannot follow the PnP re-enumeration a full init needs, the `0x90` config it was wanted for is
already recovered, and the live `d0` handshake in 5b will show the real exchange anyway. The reasoning is
kept in [`docs/windows-capture-runbook.md`](docs/windows-capture-runbook.md).

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[issues]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues
