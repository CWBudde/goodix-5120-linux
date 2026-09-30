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

**Since Run 11 (2026-09-20) the init is confirmed live all the way to `d0`**, including the 224-byte `0x90`
config, and the EC's own ClientHello confirms cipher suite `0x00ae` from the device rather than from the
driver log. **Three unknowns remain, all needing the device:** how the EC wants a server flight framed
(what Run 11 stalled on), whether it accepts our recovered PSK (still untested — the stall came first), and
the image plaintext length.

**As of 2026-09-20 the code for those runs exists and is rehearsed offline.** `internal/session` bridges
the device's TLS session to a local openssl endpoint, `goodix-probe --tls --psk …` drives it as the tail of
a bisect run, and `--capture` decodes a frame to a PGM. The whole path — handshake, rejection, image
decrypt, decode, PGM — runs against a stand-in that is a real `openssl s_client` in Goodix framing, so
what is untested is the EC's behaviour and nothing else. See Phase 5 below for what each step still needs.

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
per run, `--bisect`, external keyboard attached, owner runs it.

**5a is done on hardware (Run 11, 2026-09-20): the full vendor init runs live with the keyboard alive
throughout, and `0xd0` makes the EC open a TLS handshake.** **5b is done on hardware (Run 18, 2026-09-30):
the TLS-PSK handshake completes with the PSK unsealed from Windows, and the EC acknowledges `0xd4`.**
Every state-changing frame is behind its own `--allow-XX` flag
whose help text says what it does, and `--tls` runs as the tail of a bisect run so the bridge inherits the
keyboard checks. The runbook has the exact command lines.

- [x] **5a — Finish the init: `96`, `70`, `98`, `90`, then `d0`. Done 2026-09-20 (Run 11).** All ten frames
      went out in one run and **the keyboard stayed alive after every one of them**. `0x96` draws no reply at
      all; `0x70` answers with an ACK only; `0x98` and `0x90` answer `01 01`, so the 224-byte config
      recovered from Windows is accepted by the EC. `0xd0` makes the EC open a TLS 1.2 handshake. Details
      and the ClientHello bytes are in [`docs/protocol.md`](docs/protocol.md), Run 11.
- [x] **5b — TLS-PSK handshake against the device. (The decision point for the whole project.) Done
      2026-09-30 (Run 18): the handshake completed in 76 ms, 4 records each way, and `0xd4` was ACKed, with
      the keyboard alive throughout. The recovered PSK is the device's key, so the fallbacks below are
      not needed on this machine.** The history that got here:
      **Attempted 2026-09-20 (Run 11): the EC opened a handshake and it stalled before the PSK was used, so
      the question is still open.** The EC's ClientHello confirms `0x00ae` from the device itself and shows a
      minimal stack: empty session id, two cipher suites, **no extensions field at all**. The host's
      ServerHello + ServerHelloDone went out as two `0xb0` packs; the EC answered with a zero-length transfer
      and then nothing, and **sent no alert** — which is what a stack does when it is waiting, not when it
      fails to parse. *Changed since:* handshake records are logged
      in full (they carry no image and no key) so a stall can be reproduced offline, as Run 11's was.
      **Revised 2026-09-30 from the driver log** (`docs/protocol.md`, "The vendor's handshake"):
      the vendor sends one pack per record, as Run 11 did, and its server flight has the same contents as
      openssl's, ServerKeyExchange absent too. So the one-pack change is reverted, and the contents are
      no longer suspects. **Run 17 (2026-09-30)** ran the vendor's full init, `0xe4` included: the EC sent
      its ClientKeyExchange and then stalled, because the bridge stopped reading the device for 250 ms
      while it waited on openssl. Run 11 stalled on the same blind window one message earlier. Fixed: the
      bridge reads the EC throughout its flight. **Run 18 confirmed the fix.** *Open:* the state the EC is left
      in after a *completed* handshake that the host drops without a TLS close. Check it with `--read-state` before the 5c run.
      **Run 12 adds a procedural rule: cold power cycle after every stalled handshake.** The EC comes out of
      `0xd0` unable to answer plaintext commands — `0xae` only — and a reset does not clear it; Run 12 sent
      the init into that state and lost the keyboard. A bisect run now health-checks the EC with `0xa8` after
      attach and refuses to send anything if it does not answer. **Run 14 (2026-09-20 19:17): the stuck
      state survived a cold power cycle too**, and the one real EC reset on record likely came from a
      watchdog, not the power button. **Run 16 (2026-09-30) recovered it: shutdown with the charger
      plugged in and a 40 s power-button hold.** That is now the EC reset in the runbook, and every
      stalled `--tls` run needs one, confirmed by `--read-state`, before the next.
- [x] **5c — Capture and decode one real frame. Done 2026-09-30 (Run 20): `0x20` returned one 7744-byte
      record that decrypted to 7693 bytes, so the layout is wrapped (8-byte header + 5-byte trailer around
      7680 bytes of samples); the 80×64 PGM was written. What the header and trailer hold is still open.** *Built:* `--capture FILE` sends `0x20`, decrypts,
      trims and writes a PGM (`0600`, gitignored). `image.TrimFrame` decides bare (7680) against wrapped
      (7693) from the length that arrives and refuses to guess an offset. The 7744-byte record was
      reproduced exactly from a synthetic 7680-byte frame, so the padding arithmetic is now verified
      against openssl rather than only calculated. *To do:* the live run, and **write the plaintext length
      down** — it is the measurement that settles the layout.
- [ ] **5d — Finger-detection (FDT) loop.** Not started, and deliberately last. `proto.EncodeFDTArm` and
      `DecodeFDTEvent` exist, but an arm carries six per-zone thresholds the vendor derives at runtime from
      the previous readings, so there is no vendor payload to copy — the thresholds have to come from real
      FDT events, which means 5c first. Then implement the `32` / `20` / `34` loop so a capture is
      triggered by touch.

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
