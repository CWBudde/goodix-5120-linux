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
initial health check. Per-step key-press checks were removed on 2026-10-01; passive counters
do not establish keyboard health or continued EC responsiveness. The runbook has the exact command lines.

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
   vectors. **Run 26 completed authenticated C TLS and `0xd4`, then the immediate MCU status `0x00`
   exposed an overly strict local gate. That gate is corrected and verified offline. Run 27 (`d6a9701`)
   then reached the touch and an ACKed `0x20`, but no image record came; the EC's TLS bit stayed clear,
   so it likely never treated the C session as established (`docs/protocol.md`, Run 27). The final TLS
   flight and `0xd4` now follow the Go timing of Run 18; Runs 28/29 ran that and still got no image.
   Remaining Go difference: Go read IN for 5 s after the `0xd4` ACK; C sent `0xae` within 1 ms. The
   driver now listens 5 s there too; Run 30 ran that and still got no image, bit still clear. Every Go
   session that drew an image started with the bit already set; next: a Go capture from today's
   bit-clear state, to tell a C difference from an EC-state one (`docs/protocol.md`, Run 30). Run 31,
   that Go capture, got an image from the same state: the C session is at fault. Every failing C run
   has two host writes within ~1 ms; Go's are ≥2.5 ms apart (Run 31's timing table). The driver now
   paces ChangeCipherSpec/Finished by 60 ms too, so no two host writes are under 10 ms apart; next:
   one C capture with `dist/goodix-owner-c-gaps/`. Run 32 ran it: first C image (decrypted, 7693
   bytes), but from a bit-set start state left by Run 31, and NBIS found no minutiae, so nothing
   was saved (`docs/protocol.md`, Run 32). Run 33, the A/B run of the unpaced listen bundle from the
   same bit-set state, got no image and left the bit clear: the final-flight pacing is the fix.
   Run 34 ran `dist/goodix-owner-c-stretch/` (per-frame 1st/99th-percentile contrast stretch) from
   that bit-clear state: the session set the bit itself, NBIS accepted the stretched frame (bounds
   1468..2756) and the image was saved — **the first complete C capture**. Next: Phase 6c
   (repeated captures, enrollment, verification).** The owner-only enroll/verify procedure is
   [docs/c-driver-enroll-verify.md](docs/c-driver-enroll-verify.md), using `dist/goodix-owner-c-enroll/`.
   Run 35 enrolled a finger in C (labelled right middle, physically right index): 5/5 stages in one TLS session (six touches, one
   NBIS retry, one base-invalid re-arm), template saved, clean close. 
   Run 36 verified against it: the device path stayed clean (including reopen after a C close), but
   every Bozorth score was 0, NBIS's value for fewer than 10 minutiae. Matching is the open problem.
   Run 37 measured it: at most 5 minutiae per frame (mean 1.7) at every scale ×1–×5. NBIS cannot
   match on this sensor; a non-minutiae matcher (SIGFM-style) is required.
   Run 38 scored SIGFM offline-built and owner-run, with 12 touches. All of them turned out to be the same finger, so the run gave
   repeatability only and no impostor data. Every frame had plenty of keypoints (82–147). All six early touches
   matched each other, but 3 of the 6 later touches matched none of them at the fork's threshold of 24 (likely
   placement, so more enroll views are needed).
   Run 39 used two fingers: all 36 impostor pairs scored 0 (no false accepts), but only 3 of 6 genuine attempts
   matched a 5-view template, which points to coverage. Next: `g5120-sigfm 15` (14-view template, 15
   impostors) to see whether acceptance rises with template size; if so, integrate SIGFM with ~15–20 enroll stages.
   Run 40 did: genuine 14/15 against a 14-view template. One B touch (accidentally the index finger) matched. The
   other 14 B touches scored ≤ 9, so there were no true false accepts. Decision: integrate SIGFM (~15 enroll stages).
   Done offline in `9c682a6`. The driver is now a plain `FpDevice` with its own enroll (15 stages), verify, identify and
   capture. It matches with the vendored SIGFM at threshold 24, stores a validated raw-print template, and sends an
   unchanged wire sequence. 280 offline subtests pass. Next: the owner runs `dist/goodix-owner-c-sigfm-driver/` (Run 41,
   [docs/c-driver-enroll-verify.md](docs/c-driver-enroll-verify.md) "SIGFM driver"): one 15-stage enrollment, then
   verify attempts with the enrolled finger and with another finger.
   Run 41 enrolled with it: 15/15 stages in one session (about 1.4 s per touch), every touch including the last
   ended by its lift, 101–172 keypoints per view, clean close. Verification against that stored template: right
   index 6/6 `MATCH!` (best scores 1031–258594), another finger 3/3 `NO MATCH!` (all 0). **First working
   enroll + verify on Linux.** Next: verify again on another day from the same template, more impostor attempts,
   then identify and fprintd/PAM integration (still needs the PSK-provisioning decision below).
   After Run 41 testing is streamlined (owner's call, 2026-10-02): no separate health check or keyboard report,
   one `g5120` shell function, whole log pasted. Wire-level driver logging moved behind `GOODIX5120_TRACE=1`;
   the default debug log is milestones only ([runbook](docs/c-driver-enroll-verify.md), "Repeat runs").
   Run 42 used the quiet-log build: a second session against the Run 41 template, index `MATCH!` (score 43918) and
   other finger `NO MATCH!` (0). Next: fprintd through a reversible drop-in that loads this libfprint build, with no
   package replaced ([docs/fprintd.md](docs/fprintd.md)). That is the first live identify. PAM comes after it.
   Run 43 did that: fprintd enrolled the right index in 15 stages, plus one extra touch for fprintd's duplicate check
   (identify). `fprintd-verify` matched the index (score 527) and rejected another finger twice (0, 0).
   **The reader works through fprintd.** Next: PAM (`pam-auth-update --enable fprintd`).
   Open took ~8 s per fprintd operation: a 5 s listen after `0xd4` (its hypothesis was ruled out in Run 30) and
   11 × 200 ms init drains. Now 50 ms and 20 ms; open logs `open: N ms`. Run 44: open 961–968 ms, sessions fine.
   Genuine scores 1198/454/36 (the 36 traced to Run 43's poorly overlapping views), impostor 0. Run 45: re-enrolled; sudo via PAM matched a good placement (7037) and rejected an odd
   one (0; Ubuntu's `max-tries=1` then asks for the password). Open live: cancel, suspend/resume, cold-boot login.
   It reads the PSK from a file and does not provision one.
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

### 6a — Secrets and TLS correctness (complete)

- [x] **Remove secret output from the DPAPI tool.** `cmd/goodix-dpapi/main.go:113` prints the Windows
      boot key by default. Keep the boot key withheld; also reconcile default GUID / plaintext-hash
      output with the publication rules above. Add a CLI-output regression test using synthetic data.
- [x] **Keep the PSK out of process arguments.** `internal/tlspsk/tlspsk.go:213` and
      `internal/session/loopback.go:146` pass it to `openssl -psk`, making it visible through process
      inspection. Use a private in-process PSK endpoint or an interface that receives the key through
      a protected descriptor. Rehearsal should use a synthetic key when the device's key is unnecessary.
- [x] **Secure replacement of PSK and biometric output files.** `os.WriteFile(..., 0600)` in
      `cmd/goodix-dpapi/main.go:171` and `os.OpenFile(..., 0600)` in `cmd/goodix-probe/tls.go:359`
      do not restrict permissions on an existing file and follow symlinks. Create private temporary
      files and replace deliberately, or refuse existing destinations; test existing 0644 files,
      symlinks, write failures, and final ownership after `sudo` capture.
      **Implementation and offline regressions pass:** atomic private replacement, cleanup, mandatory
      ownership, and UID/GID range validation. **Owner verified final ownership under real sudo
      (2026-09-30):** the following offline check passed (`ok goodix5120/cmd/goodix-probe 0.008s`):
      `sudo env GOCACHE=/tmp/goodix-owner-cache go test ./cmd/goodix-probe -run TestCaptureSudoOwnershipOnDisk -count=1`.
      It writes a synthetic image without USB access and checks the invoking user's UID/GID and
      mode `0600` on disk. This closes the remaining Phase 6a acceptance check.
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
actual USB driver and hardware remained untested at that point. The owner has now passed the real
sudo ownership check above, completing Phase 6a. Phase 6b / 6c gates still apply.

### 6b — Exercise and harden the actual libfprint driver (complete)

- [x] **Add an offline fake USB / libfprint lifecycle harness for `goodix5120.c`.** Previously, standalone
      Meson tests compiled only the protocol and TLS helpers. Exercise open, activation, touch → image →
      lift, multiple enrollment stages, cancellation in every state, unplug, timeouts, wrong ACKs,
      unexpected messages, and reopen. Use synthetic images and keys; no private capture is required.
      **Done 2026-09-30:** the actual driver compiles as a separate translation unit against a
      test-only GLib/GObject adapter; real protocol/TLS/image helpers and an OpenSSL client exercise
      synthetic open and enrollment. Transfer sweeps cover unplug at every open boundary and
      cancellation / I/O failure through capture and lift; state hooks cover all FDT/capture states.
      See [`libfprint/goodix5120/tests/README.md`](libfprint/goodix5120/tests/README.md) for the adapter
      contract and exclusions. Real libfprint/GUsb integration and hardware remain unverified.
      **Verified:** all 39 lifecycle and 43 helper subtests pass, also under ASan/UBSan with leak
      detection disabled under ptrace; `just check` and Go race tests pass. Independent review caught
      two adapter ordering/cancellation gaps, now covered by regressions. Mutation checks confirm
      tests reject negative-ACK acceptance, missing session cleanup and post-cancellation rearming.
      At that point the remaining 6b items below and the owner-only sudo check in 6a stayed open.
- [x] **Validate init reply contents before continuing.** `xchg_recv_cb` previously accepted any
      correctly framed data payload with the expected command after its ACK. Validate known response
      lengths and status fields, including chip ID. `OPEN_LOG_MCU_STATE` must refuse a truncated state
      or an unexpected post-handshake status instead of succeeding with a warning. Tests must verify that
      no subsequent command is written after a rejected response.
      **Done 2026-09-30:** both firmware replies require the exact supported name with an optional
      trailing NUL; all init data replies require their documented lengths. Reset / DAC / config
      status bytes, chip ID `0x2504`, and the PSK-hash type/length header are checked before advancing
      the exchange. The original final-state gate required the TLS-connected bit; Run 26 corrects
      that assumption for the immediate status `0x00` after authenticated TLS and a positive `0xd4` ACK.
      Hash, OTP and MCU counters
      remain opaque; no new device commands were introduced. **Run 23 correction:** the PSK reply's
      observed nine-byte prefix is recorded in Run 8; the prior eight-byte request-echo header and
      supposed trailing byte were a transcription error (see the owner-run follow-up below).
      **Verified:** 68 added lifecycle cases cover empty / short / oversized replies, every known
      status/header byte, hidden firmware suffixes, and valid opaque-field variation. Rejection
      asserts no later USB write, one failed open, and no pending transfer. Before the fix, 57 cases
      failed as expected. All 107 driver and 43 helper subtests now pass, also under ASan/UBSan with
      leak detection disabled under ptrace; `just check` and Go race tests pass (existing formatting
      differences remain). Independent review found no actionable issues. Four mutation checks
      catch missing validation, unchecked chip ID, an unset TLS bit, and a non-NUL terminator.
      At that point five 6b tasks still gated the first hardware run; the owner has passed the 6a sudo check.
- [x] **Invalidate failed sessions.** After an image / TLS / transport failure, `session_done` previously
      retained the TLS object and `dev_activate` treated the session as usable for another operation. Require a
      deliberate recovery / reopen boundary rather than reusing a failed session; test late image
      arrival and activation after failure. Do not invent an untested EC reset or cleanup command.
      **Done 2026-09-30:** only successful open permits operations. A session error invalidates that
      permission, discards TLS, and clears buffered plaintext before notifying libfprint, including
      errors suppressed during deactivation. Activation requires close/reopen; late capture/FDT
      transitions submit no USB work. Healthy FDT/capture cancellation remains reusable without a
      handshake. No device recovery commands were added; real EC recovery remains unverified.
      **Verified:** nine added cases plus three extended image-failure regressions exercise malformed
      TLS / ciphertext, OUT/IN failures, failure during deactivation, repeated activation, late images,
      cancellation reuse and close/reopen. Ten failure regressions failed before the fix; both new
      healthy-cancellation checks already passed. All 116 driver and 43 helper subtests pass normally
      and under ASan/UBSan (leak detection disabled under ptrace). `just check` passes with existing
      formatting differences. Independent review found no actionable issues. Four mutation checks
      catch retained session validity, late state rearming, ignored deactivation failures and broken
      healthy-cancellation reuse. At that point four remaining 6b tasks still gated the first hardware run.
- [x] **Fix capture-read budget ordering.** `cap_read_cb` previously rejected the fourth additional transfer
      before attempting to decrypt the bytes it just fed. Try decoding the newly completed record
      before declaring the read budget exhausted; test completion on the final permitted read.
      **Done 2026-09-30:** decrypt newly fed bytes before checking the additional-read budget. Two new cases
      cover a complete image and invalid layout on the final permitted read; both failed before the fix.
      The six-fragment exhaustion case still leaves its last fragment unread; no read limit was increased.
- [x] **Reset per-operation FDT retry state.** `base_invalid` was reset only on accepted finger-down.
      A retry after exhausting that budget inherits the exhausted count. Reset it at the intended
      operation / session boundary and test a retry after failure.
      **Done 2026-09-30:** successful activation starts a fresh retry budget; rearming keeps its count.
      Two new cases retry after cancellation/reactivation and exhausted-budget failure/close/reopen.
      Both failed before the fix; each now permits eight base-invalid rearms before accepting finger-down.
- [x] **Restore detached kernel drivers on release.** Claim uses
      `G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER`, but close and open-failure cleanup previously released with
      flags zero. Track successful claim / detach ownership and release symmetrically. Test rollback
      on open failure and close with a previously bound driver.
      **Done 2026-09-30:** track successful claims and use the matching binding flag for close and rollback.
      Preclaim/failed-claim paths never release an unowned interface. Cleanup failure is reported, preserving
      the original open error on rollback; ambiguous ownership prevents reopening that device object.
      **Verified for this three-item batch:** 10 new and 11 extended lifecycle cases cover final image reads,
      fresh FDT retries, binding restoration requests, unowned cleanup, and release/attach failures. Thirteen
      targeted cases failed before their fixes. All 126 driver and 43 helper subtests pass normally and under
      ASan/UBSan (LeakSanitizer disabled under ptrace); `just check` passes with existing formatting differences.
      Seven mutation checks catch early exhaustion, a widened limit, retained retries, unowned release,
      missing binding flags, reopening after cleanup failure, and hidden rollback errors. Independent
      review found no actionable issues and confirmed the real libfprint completion contracts.
      **API limitation:** GUsb can detach before an unsuccessful claim with no rollback or public separate
      attach API. Tests verify successful-claim release symmetry; real restoration remains unverified.
      At that point the shared-fixture task below still gated the first C-driver hardware run.
- [x] **Use independent shared protocol fixtures.** Compare every init payload byte, reply expectation,
      FDT vector, and image layout between Go and C. Selected payload assertions and a config checksum
      cannot establish full byte-for-byte parity.
      **Done 2026-09-30:** Go and C consume an independent committed INI corpus. All 14 ordered init
      requests, every config byte, reply modes/data/secret classifications, the health check and capture
      catalogue are pinned. A real-driver lifecycle scenario checks all 15 open command payloads and
      receives corpus replies through its existing synthetic OpenSSL peer. Malformed-init regressions
      retain the no-later-write requirement, now starting from shared valid reply data.
      FDT references include three arm vectors, ten events and 21 event-to-arm pairs, including Run 22,
      both deltas, uncovered zones, saturation and timestamps. Synthetic image references check all 5120
      samples and grayscale pixels, 64-column × 80-row geometry, bare/wrapped layouts, offsets and six
      invalid lengths. Loaders reject missing/duplicate/incomplete records and malformed values.
      **Verified:** all 211 C subtests pass normally and under ASan/UBSan (LeakSanitizer disabled under
      ptrace). `just check`, Go race tests and the shared FDT tests under both opcode tags pass; existing
      formatting differences remain. Fourteen mutation checks catch seven drift classes in both languages:
      checksum-preserving config changes, init order, reply modes, thresholds, timestamp endianness,
      image offsets and sample packing. Independent review found no critical/important issues.
      Shared Go FDT integration tests live in `internal/testfixtures` to preserve the protocol package's
      standard-library-only import rule. Runtime reply handling and safety gates are unchanged.
      **Optional follow-up:** pin the Go capture-loop replay's ACK/TLS reply shapes directly to the extra
      `loop.image` reference; all 14 init reply expectations are already compared.

**Phase 6b offline gate complete.** The next step is one owner-run C-driver capture using the
[driver's first-live-run procedure](libfprint/goodix5120/README.md#first-live-run-owner-only-keyboard-safe-procedure)
and the external-keyboard runbook. Agents must not run hardware. Driver timing, EC recovery,
calibration portability and authentication quality remain unverified; Phase 6c precedes PAM use.

**Prepared 2026-09-30:** current driver `c1aee77` compiles against pinned real libfprint
`6f9479c3d55f847c1b3769f28ceb99227f9858cf` with only `goodix5120` enabled. The device-table tool
lists only `27c6:5120`; the capture executable resolves the build's own library. No installation or
hardware access occurred. The ignored local bundle in `dist/goodix-owner-c-c1aee77/` survives reboot.
See [the concrete owner capture runbook](docs/c-driver-first-capture.md)
for commands and acceptance evidence, including the upstream example's misleading failure exit
status. The owner capture is still pending; no Phase 6c hardware criterion is closed.

**Owner attempt 2026-09-30 (Run 23):** the Go health check passed. C open received ACK + 41 bytes
for `0xe4` but rejected its header before TLS or capture; both keyboards still worked after exit.
Offline investigation found that the validator and shared Go/C fixtures had misread the reply as
the request's type. They now use Run 8's literal nine-byte prefix `00 03 00 01 bb 20 00 00 00`
plus a synthetic 32-byte hash; all nine prefix bytes and the exact 41-byte length are checked.
The former request-echo shape is rejected, hash bytes remain opaque, and secret redaction is unchanged.
The new Run 8 regression failed with the same open error before the fix. All 214 offline C subtests
pass normally and under ASan/UBSan (leak detection disabled under ptrace); `just check` passes with
the existing formatting listings. A corrected owner capture remains pending. The local `fuseblk`
mount does not enforce private modes, so capture images/logs use the owner's Linux home filesystem.
Corrected driver `a8a29a3` also compiles against pinned real libfprint without compiler warnings;
the ready bundle is `dist/goodix-owner-c-e4-fix/`, with exact revisions and binary checksums.

**Owner attempt 2026-09-30 (Run 24):** fresh Go health checks passed; driver `a8a29a3` passed the
full C init, confirming the `0xe4` correction. After ClientHello (52 bytes), ServerHello (86) and
ServerHelloDone (9), the EC sent fatal `decode_error (50)`. No ClientKeyExchange, `0xd4` or capture
followed. Both keyboards still worked; recovery is required before another owner hardware attempt.
An offline synthetic first-flight comparison found C and Go TLS contents identical apart from
random/session-ID bytes. C's whole-frame OUT submissions differed from Go's completed 64-byte writes.
**Cause remains unproven:** the C config write already passed with a 256-byte submission.

Candidate `e8930b4` now completes one 64-byte OUT at a time, with unchanged frame bytes, no retries
or artificial delays, and one bounded 2000 ms budget for the complete frame. Explicit completion-length
checks reject zero writes that pinned libfprint's `short_is_error` omits. The peer assembles completed
packets without hiding raw submissions; 18 added cases cover granularity, all four config packets
under short/zero/I/O/cancel failure, and aggregate budget exhaustion. The packet-size regression failed
before the change; the zero-completion regression failed without the production guard. **Verified:**
232 C subtests pass normally and under ASan/UBSan (leak detection disabled under ptrace), `just check`
passes with existing formatting listings, and pinned real libfprint compiles without compiler warnings.
The reviewed offline candidate bundle was `dist/goodix-owner-c-packet-writes/`; independent review found no remaining
blocking issues after the zero-write guard. These offline tests establish neither a successful
capture nor enrollment, matching or a Phase 6c criterion.

**Owner attempt 2026-10-01 (Run 25):** after a reported reboot and passing 05:39 Go health/keyboard
checks, candidate `e8930b4` passed the full C init and again received fatal `decode_error (50)`
after its 86/9-byte first server flight. No ClientKeyExchange, `0xd4`, finger arm or image followed;
both keyboards worked after exit. The packet-submission change did not resolve the failure.
Post-failure EC health remains unverified; hardware retries are deferred while diagnosis proceeds.

The previous first-flight comparison used current Go's memory-BIO endpoint, whereas the successful
live Go runs used historical `openssl s_server`. A synthetic comparison with that actual CLI and
pure helpers from the owner bundle now verifies matching first-flight structure and padded frames.
Normalization conceals one protocol-semantic random suffix: the CLI's TLS-1.3-capable context emits
`DOWNGRD\x01`, C's TLS-1.2-only context does not. This is not a confirmed cause; no protocol/random-byte
change or arbitrary delay is warranted. See Run 25 in `docs/protocol.md` for limits and evidence.

- [ ] **Diagnose the live C first-flight rejection before another candidate run.** Add targeted,
      sanitized diagnostics for ClientHello/ServerHello structure and each completed OUT packet's
      frame/offset/length/timing. Independently verify the production helper → frame → completed
      packet path offline. Keep raw transfer tracing disabled, TLS bytes unmodified and secret/
      application payloads withheld. A candidate must address demonstrated evidence; the existing
      owner review/health gate still applies before any future hardware experiment.
      **2026-10-01:** owner analysis identifies logged inter-record spacing as a timing hypothesis:
      vendor 61/66 ms, Go ~3 ms (completed), C within adjacent logging milliseconds in Runs 24/25
      (`decode_error`). These timestamps do not measure USB completion or establish a minimum gap.
      The candidate enforces a 60 ms interval between host records while reading IN; stale/empty input
      cannot shorten or restart it. Partial TLS input is completed before more output. Every handshake
      state, read and frame write respects the remaining total budget. Record counts describe progress
      when an alert is observed, without assigning causality. Two original and eleven additional regressions
      cover flight boundaries, immediate/split alerts, noise, elapsed intervals and budget failures.
      **245 C subtests pass offline.** The owner reports the original pacing bundle crashed the EC;
      its final error is not available. Run 26 subsequently completed TLS with the reviewed revision;
      targeted structure/packet diagnostics remain open as follow-up evidence, not a demonstrated blocker
      to the immediate MCU-state fix. The owner review/health gate is unchanged.

**Prepared for the owner's requested test, 2026-10-01:** the owner reports the EC healthy and
requests one real-hardware test of reviewed driver `2b77542`. Exact committed sources now compile
against pinned libfprint `6f9479c3d55f847c1b3769f28ceb99227f9858cf` without compiler warnings.
Fresh normal and ASan/UBSan runs pass all 245 C subtests (leak detection disabled). The ignored
bundle `dist/goodix-owner-c-2b77542/` has verified source hashes, binary checksums, host library
resolution and a driver table containing only `27c6:5120`. No hardware access or system installation
occurred during preparation. The [capture runbook](docs/c-driver-first-capture.md) now uses this
revision. The owner result is recorded below; targeted diagnostics remain follow-up work.

**Run 26, 2026-10-01 08:03:** driver `2b77542` completed authenticated TLS (four records each way),
received `0xd4` ACK status `0x01`, and immediately received a valid 20-byte MCU reply with status
`0x00`. The local TLS-bit gate then rejected open before finger arming or image capture. Both keyboards
still typed after exit; this log does not establish an EC wedge or a need to reboot. No post-exit
firmware health check is recorded. The 60 ms intervals are observed, but their causal role/minimum is unknown.

**Immediate MCU-state correction:** accept exactly status `0x00` at that post-authentication gate,
while retaining exact length, authenticated peer Finished, completed host records, and positive
`0xd4` ACK requirements. Other bit-clear statuses, including stuck `0x08`, remain rejected. The bit
decoder, commands, delays and retries are unchanged; Go does not make this immediate query.
Independent review found no blocker. The literal owner reply now passes a synthetic encrypted
capture → lift → close regression; four rejected-status cases and a negative `0xd4` ACK guard refusal.
All 251 C subtests pass normally and under ASan/UBSan (leak detection disabled); `just check` passes
with existing formatting listings. Actual C image capture and Phase 6c remain unverified.

**Corrected owner bundle prepared:** `dist/goodix-owner-c-d6a9701/` contains exact fix commit
`d6a9701af7355e31d67cce3066f490fec0278fa2` and the same pinned libfprint. The real integration compiles
without compiler warnings. Verified committed source/fixture hashes, host library resolution, the sole
`27c6:5120` driver ID and binary checksums are recorded with build/test logs. No agent ran hardware.
The [capture runbook](docs/c-driver-first-capture.md) uses this revision; one real C capture remains next.

### 6c — Portability, authentication quality, and repeatable checks

- [ ] Derive DAC settings and FDT delta from OTP, or explicitly restrict this prototype to a supported
      per-device profile. Matching firmware alone does not establish matching calibration. Reconcile
      committed device-specific DAC constants with the publication policy before upstream submission.
- [ ] Validate ridge polarity, contrast, minutiae yield, enlargement, enrollment stages, and match
      threshold on owner-controlled hardware. First step: [enroll and verify](docs/c-driver-enroll-verify.md)
      with libfprint's examples (5 stages in one session, one genuine and one impostor verify). Measure repeated genuine-finger and different-finger
      attempts before enabling PAM; a recognizable image and three captures do not validate matching.
- [ ] Validate repeated open / close, cancellation and immediate reuse, suspend / resume, and autosuspend
      under the owner-only procedure after the offline gate passes. Record recovery behavior in the docs.
- [ ] Harden offline parsers: compare DPAPI master-key lengths before conversion to `int`
      (`internal/dpapi/dpapi.go:319`), bound key-stretch work, and reject cyclic / excessively deep registry
      subkey indexes (`internal/winreg/hive.go:155`). Add malformed-input tests and a winreg test suite.
- [ ] Bound Go bridge socket writes and the background plaintext buffer, so cancellation and size
      limits apply while I/O is in progress. Exercise backpressure.
- [ ] Make ordinary Go bisect steps stop when their documented ACK/data reply is missing. Preserve
      legitimate no-reply (`0x96`) and ACK-only commands; add regressions proving no later step or TLS
      hook runs after a missing required reply. The initial health check does not cover later failures.
- [ ] Add repeatable checks for Go tests / race / vet, both opcode tags, C helper tests / sanitizers,
      and compilation against a pinned libfprint revision. Make format checking fail on differences;
      `just fmt-check` currently only prints filenames. Refresh the root README's obsolete stop verdict,
      dimensions, layout, and unused-scaffold descriptions to match the completed Go bring-up.

---

## Recommended order

1. ~~**Phase 6, layer 1** — `--touches` live: several frames in one session.~~ Done (Run 22).
2. ~~**Phase 6 review, 6a and 6b** — offline secret handling, TLS fixes, response validation, and
   actual-driver lifecycle tests.~~ Complete; the Run 26 gate correction is also verified offline.
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
