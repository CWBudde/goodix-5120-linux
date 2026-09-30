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

## Where we stand (2026-09-30)

**The sensor works on Linux, end to end, from the Go probe.** Runs 18–21 did the vendor init, completed
the TLS-PSK handshake with the key unsealed from Windows, captured and decoded frames (64 × 80), and ran
the finger-detect loop — all with the internal keyboard alive, and three init + handshake cycles in a row
with no EC reset in between. Phase 5 is done; what is left is Phase 6 (the driver) and Phase 2 (publish).

- **Device:** an ITE EC (`GF_ITE_EC_20063`) in front of a Goodix sensor, chip ID `0x2504`, 64 columns ×
  80 rows. Treated as an "EC project": no `nop`, no firmware update, ever.
- **The wedge is understood and defused:** `0xe4` sent without its 8-byte argument. The transport cannot
  build that frame. An unfinished TLS handshake leaves the EC stuck until an EC reset (charger plugged in,
  40 s power-button hold), so every live run health-checks the EC first.
- **Several frames in one TLS session work** (Run 22, `--touches 3`), which is what enrolment needs.
- **Still open on hardware:** a base-invalid re-arm seen live, and what the 8-byte header and 5-byte
  trailer around each frame hold.

## Completed phases (detail is in the docs, not here)

| Phase | Result | Where |
|---|---|---|
| 1 — offline code fixes | done 2026-09-19 | `CLAUDE.md`, `docs/protocol.md` |
| 3 — passive research (driver log, USB captures, ACPI, `0x90`, DPAPI seal) | done | `docs/protocol.md`, `docs/acpi.md`, `docs/windows-capture-runbook.md` |
| 3b — bisect the wedge (Runs 2–4) | done 2026-09-19 | `docs/protocol.md`, `docs/bisect-runbook.md` |
| 3c — align code with the vendor sequence | done 2026-09-19 | `CLAUDE.md`, `cmd/goodix-probe/vendor.go` |
| 4 — live plaintext runs, steps 1–4 (Runs 5–10) | done 2026-09-20 | `docs/protocol.md` |
| 5 offline — PSK unseal + wire, TLS suite, image decode | done 2026-09-20 | `docs/dpapi-runbook.md`, `docs/protocol.md` |
| 5 live — init, handshake, frame, finger detection (Runs 11–21) | done 2026-09-30 | Phase 5 below, `docs/protocol.md` |

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
      7680 bytes of samples); the frame shows a clear fingerprint read as **64 columns × 80 rows** (the probe had it as 80×64, now fixed). What the header and trailer hold is still open.** *Built:* `--capture FILE` sends `0x20`, decrypts,
      trims and writes a PGM (`0600`, gitignored). `image.TrimFrame` decides bare (7680) against wrapped
      (7693) from the length that arrives and refuses to guess an offset. The 7744-byte record was
      reproduced exactly from a synthetic 7680-byte frame, so the padding arithmetic is now verified
      against openssl rather than only calculated. *To do:* the live run, and **write the plaintext length
      down** — it is the measurement that settles the layout.
- [x] **5d — Finger-detection (FDT) loop.** **Run 21 (2026-09-30) ran it live:** touch → frame → lift,
      with the derived up thresholds matching the rule in all six zones, and the keyboard alive. Run 22
      then showed the up arm waiting for a finger that is still down. Still unseen live: a base-invalid
      re-arm.
      The threshold rules turned out to be recoverable from `dump.pcapng` and the driver log (68 of 68
      arms reproduced; `docs/protocol.md`, "Finger detection: where the thresholds come from"), so real
      FDT events were not needed first. `goodix-probe --wait-finger` (behind `--allow-32 --allow-34`)
      runs `32` → `20` → `34` once, re-arming on base-invalid; rehearsed offline. The live command is in
      `docs/bisect-runbook.md`.

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
   **Status (2026-09-30):** the pipeline runs live once round (Run 21). The probe keeps `--bisect` as its
   only mode that sends anything (the Run 1 mode and `--tls-coalesce-flight` are gone), and it stays
   until the C driver has run on hardware.
   - [x] **Several prints in one session.** Done 2026-09-30 (Run 22): `--touches 3` took three frames
     after one handshake, with the up arm waiting for a real lift each time.
   - [ ] The 13 bytes around each frame: the probe now logs them, so the next `--touches` run can
     compare them across frames.
2. **libfprint driver (C, upstream).** `fprintd` on top of libfprint is the only realistic path to
   enrollment, minutiae matching (libfprint's bundled NBIS) and PAM. Contribute a `goodix5120` driver
   modelled on the existing Goodix drivers and the community `goodixtls` work for the TLS 5xx parts. A
   libfprint out-of-tree **TOD** module is the fallback only if upstream declines the driver.
   *Started (2026-09-30):* [`libfprint/goodix5120/`](libfprint/goodix5120/README.md) is a first
   `goodix5120` image driver. It compiles in a libfprint tree, and its framing, send gate, FDT
   thresholds, 12-bit decode and in-process TLS-PSK server are unit-tested offline against this repo's
   vectors. **It has not run on hardware.** It reads the PSK from a file and does not provision one.
   Its README lists what is stubbed and the open questions for the first live run.
   **Review gate (2026-09-30):** finish the offline hardening and lifecycle checks below before
   the first C-driver hardware run. Passing the pure helper tests does not exercise the driver itself.

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

## Phase 6 review follow-up — offline first (2026-09-30)

These are implementation tasks from the code review, not new hardware observations. Keep the existing
owner-only live procedure and the prohibition on firmware writes. Do not make the driver part of the
default build or enable PAM while these checks and matching validation remain open.

### 6a — Secrets and TLS correctness (highest priority)

- [x] **Remove secret output from the DPAPI tool.** `cmd/goodix-dpapi/main.go:113` prints the Windows
      boot key by default. Keep the boot key withheld; also reconcile default GUID / plaintext-hash
      output with the publication rules above. Add a CLI-output regression test using synthetic data.
- [x] **Keep the PSK out of process arguments.** `internal/tlspsk/tlspsk.go:213` and
      `internal/session/loopback.go:146` pass it to `openssl -psk`, making it visible through process
      inspection. Use a private in-process PSK endpoint or an interface that receives the key through
      a protected descriptor. Rehearsal should use a synthetic key when the device's key is unnecessary.
- [ ] **Secure replacement of PSK and biometric output files.** `os.WriteFile(..., 0600)` in
      `cmd/goodix-dpapi/main.go:171` and `os.OpenFile(..., 0600)` in `cmd/goodix-probe/tls.go:359`
      do not restrict permissions on an existing file and follow symlinks. Create private temporary
      files and replace deliberately, or refuse existing destinations; test existing 0644 files,
      symlinks, write failures, and final ownership after `sudo` capture.
      **Implementation and offline regressions pass:** atomic private replacement, cleanup, mandatory
      ownership, and UID/GID range validation. Final ownership under real sudo remains unverified:
      `TestCaptureSudoOwnershipOnDisk` is skipped without root; passwordless sudo is unavailable here.
      Owner-only offline check (synthetic image, no USB):
      `sudo env GOCACHE=/tmp/goodix-owner-cache go test ./cmd/goodix-probe -run TestCaptureSudoOwnershipOnDisk -count=1`.
- [x] **Fix C TLS record boundaries across feeds.** `goodix5120_tls.c:337` treats each fragment as a
      record boundary. A valid encrypted image split at a ciphertext byte that resembles an alert
      is rejected before OpenSSL can reassemble it. Track boundaries across calls or leave alert
      interpretation to OpenSSL. Test partial headers, every split position, and concatenated records.
- [x] **Validate effective TLS policy before USB writes.** `goodix5120_tls.c:223` treats successful
      `SSL_CTX_set_cipher_list()` as capability; security level 3 can accept that setter and then reject
      the same suite during handshake. Fail offline with a policy-specific error if the suite is
      unavailable, and distinguish local policy failures from likely PSK mismatch. Test multiple
      security levels; do not silently weaken policy without a deliberate compatibility decision.
- [x] **Preflight the Go TLS endpoint before live init.** Load and validate the PSK before opening
      hardware, rather than first doing so in the post-init `runTLS` hook. Confirm that the bridge
      connects to its own subprocess: `tlspsk.Start` currently accepts a connection to an occupied
      port even when its OpenSSL child cannot bind. Establish listener ownership, detect child startup
      failure, retain bounded diagnostics, and test a prebound port.
- [x] **Bound and validate TLS framing in both implementations.** Reject invalid record types / versions
      and records too large for the outer 16-bit length in the C send helper (`goodix5120_proto.c:129`).
      Guard encoder failure before padding. The Go transport also needs an aggregate TLS-pack size
      check: `SendTLS` can accept several valid records totalling more than 65535 bytes, while
      `proto.EncodePack` truncates the declared length. Add boundary tests for both implementations.
- [x] **Account for libfprint's transfer tracing.** Driver-level redaction does not stop
      `FP_DEBUG_TRANSFER` plus debug logging from dumping the raw `0xe4` / `0xa6` replies through
      the USB helper. Establish a supported way to prevent sensitive transfer dumps, or explicitly
      document this limitation and keep it out of the recommended debugging procedure.

**Implemented / verified (2026-09-30):** native OpenSSL server and rehearsal client; synthetic
rehearsal keys; effective policy checks before USB (including configured protocol and cipher
restrictions); DPAPI redaction; private file replacement; C stream-boundary tracking; bounded TLS
framing; transfer-tracing limitation documented. Independent review found a policy-override gap;
regression tests caught it and the correction passed re-review. Go tests / race / vet, supported
opcode tags, command builds, and all 43 standalone C subtests pass. ASan/UBSan pass with leak
detection disabled because LeakSanitizer cannot operate under sandbox ptrace. Offline three-touch
capture and mismatched-key rejection pass. Private-capture / Windows fixtures were not used; the
actual USB driver and hardware remain untested here. The real sudo ownership check above is the
remaining 6a acceptance check. Phase 6b / 6c gates still apply.

### 6b — Exercise and harden the actual libfprint driver

- [ ] **Add an offline fake USB / libfprint lifecycle harness for `goodix5120.c`.** The standalone
      Meson tests compile only the protocol and TLS helpers. Exercise open, activation, touch → image →
      lift, multiple enrollment stages, cancellation in every state, unplug, timeouts, wrong ACKs,
      unexpected messages, and reopen. Use synthetic images and keys; no private capture is required.
- [ ] **Validate init reply contents before continuing.** `xchg_recv_cb` currently accepts any
      correctly framed data payload with the expected command after its ACK. Validate known response
      lengths and status fields, including chip ID. `OPEN_LOG_MCU_STATE` must refuse a truncated state
      or an unset `isTlsConnected` bit instead of succeeding with a warning. Tests must verify that
      no subsequent command is written after a rejected response.
- [ ] **Invalidate failed sessions.** After an image / TLS / transport failure, `session_done` retains
      the TLS object and `dev_activate` treats the session as usable for another operation. Require a
      deliberate recovery / reopen boundary rather than reusing a failed session; test late image
      arrival and activation after failure. Do not invent an untested EC reset or cleanup command.
- [ ] **Fix capture-read budget ordering.** `cap_read_cb` rejects the fourth additional transfer
      before attempting to decrypt the bytes it just fed. Try decoding the newly completed record
      before declaring the read budget exhausted; test completion on the final permitted read.
- [ ] **Reset per-operation FDT retry state.** `base_invalid` is reset only on accepted finger-down.
      A retry after exhausting that budget inherits the exhausted count. Reset it at the intended
      operation / session boundary and test a retry after failure.
- [ ] **Restore detached kernel drivers on release.** Claim uses
      `G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER`, but close and open-failure cleanup release with
      flags zero. Track successful claim / detach ownership and release symmetrically. Test rollback
      on open failure and close with a previously bound driver.
- [ ] **Use independent shared protocol fixtures.** Compare every init payload byte, reply expectation,
      FDT vector, and image layout between Go and C. Selected payload assertions and a config checksum
      cannot establish full byte-for-byte parity.

### 6c — Portability, authentication quality, and repeatable checks

- [ ] Derive DAC settings and FDT delta from OTP, or explicitly restrict this prototype to a supported
      per-device profile. Matching firmware alone does not establish matching calibration. Reconcile
      committed device-specific DAC constants with the publication policy before upstream submission.
- [ ] Validate ridge polarity, contrast, minutiae yield, enlargement, enrollment stages, and match
      threshold on owner-controlled hardware. Measure repeated genuine-finger and different-finger
      attempts before enabling PAM; a recognizable image and three captures do not validate matching.
- [ ] Validate repeated open / close, cancellation and immediate reuse, suspend / resume, and autosuspend
      under the owner-only procedure after the offline gate passes. Record recovery behavior in the docs.
- [ ] Harden offline parsers: compare DPAPI master-key lengths before conversion to `int`
      (`internal/dpapi/dpapi.go:319`), bound key-stretch work, and reject cyclic / excessively deep registry
      subkey indexes (`internal/winreg/hive.go:155`). Add malformed-input tests and a winreg test suite.
- [ ] Bound Go bridge socket writes and the background plaintext buffer, so cancellation and size
      limits apply while I/O is in progress. Exercise backpressure. Keep the keyboard check on the
      ordinary bisect send / receive error path, as the TLS hook already does.
- [ ] Add repeatable checks for Go tests / race / vet, both opcode tags, C helper tests / sanitizers,
      and compilation against a pinned libfprint revision. Make format checking fail on differences;
      `just fmt-check` currently only prints filenames. Refresh the root README's obsolete stop verdict,
      dimensions, layout, and unused-scaffold descriptions to match the completed Go bring-up.

---

## Recommended order

1. ~~**Phase 6, layer 1** — `--touches` live: several frames in one session.~~ Done (Run 22).
2. **Phase 6 review, 6a and 6b** — offline secret handling, TLS fixes, response validation, and
   actual-driver lifecycle tests. These precede the first C-driver hardware run.
3. **Phase 6, layer 2** — owner runs one C-driver capture, then validates repeated lifecycle and
   enrollment / matching behavior under 6c. PAM comes after matching validation.
4. **Phase 2** — owner reviews the publication checklist and posts the drafts; this can proceed in
   parallel with offline hardening once the secret-publication inconsistencies are resolved.
5. Device calibration portability and the PSK-provisioning decision, before the driver goes upstream.

**Dropped as no longer useful:** the standalone "capture a real init on the wire" task (old Phase 3).
USBPcap cannot follow the PnP re-enumeration a full init needs, the `0x90` config it was wanted for is
already recovered, and the live `d0` handshake in 5b will show the real exchange anyway. The reasoning is
kept in [`docs/windows-capture-runbook.md`](docs/windows-capture-runbook.md).

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[issues]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues
