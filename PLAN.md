# Plan: `27c6:5120`

**This file is the plan, not the record.** Every run and finding is in [`docs/protocol.md`](docs/protocol.md),
the first incident included (Run 1). The step-by-step history of this file is in git.

Standing rules: the owner runs everything live, never Claude. Never run upstream `driver_51x0.main()` or any IAP /
firmware-write path. `write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) stay out of every default build.

## Where we stand (2026-10-02)

**The reader works on Linux, end to end, through fprintd and PAM** (Run 45). The C driver in
[`libfprint/goodix5120/`](libfprint/goodix5120/README.md) opens in about 1 s, enrolls 15 touches, and matches with
SIGFM (threshold 24). Genuine scores so far are 36–258594, other fingers 0–9.

## Done

| Phase                                                                         | Result                                              | Runs  |
| ----------------------------------------------------------------------------- | --------------------------------------------------- | ----- |
| 1 — offline code fixes; send gate with payload rules                          | the empty `0xe4` that wedged the EC cannot be built | —     |
| 3 — passive research: driver log, USB captures, ACPI, `0x90` config, DPAPI    | vendor init and handshake read from the Windows log | —     |
| 3b — bisect the wedge                                                         | `0xe4` without its argument                         | 2–4   |
| 4 — live plaintext init                                                       | keyboard alive through every step                   | 5–10  |
| 5 — PSK unsealed from Windows; init, TLS-PSK, frame, finger detection from Go | 64 × 80 frames; EC reset = charger in, 40 s hold    | 11–22 |
| 6a/6b — offline hardening; fake-USB lifecycle tests of the real driver        | 280 C subtests, ASan/UBSan clean                    | —     |
| 6, C capture — TLS pacing (no two host writes < 10 ms apart)                  | first C image                                       | 23–34 |
| 6, matching — NBIS finds ≤ 5 minutiae; SIGFM in the driver                    | 14/15 genuine offline, no true impostor > 9         | 35–41 |
| 6, integration — fprintd drop-in, PAM, 1 s open                               | `sudo` by finger                                    | 42–45 |
| Tooling — bundle build in repo, CI, lint/format, release-please               | releases carry the built bundle                     | —     |

## Open

### Phase 6c — lifecycle on hardware (owner)

- [ ] **Cancel and immediate reuse.** Ctrl-C during the finger wait, and within the first second (mid-handshake),
      each followed by `sudo true`. The second is the riskiest test left: an unfinished handshake is the one state
      known to leave the EC stuck.
- [x] **Suspend / resume:** the reader opened in 501 ms after resume and matched (Run 50). The unlock screen's
      timeout was a PAM race between `gdm-password` and `gdm-fingerprint`, fixed in the installer. Check that the next
      resume shows the fingerprint prompt at once. Still open: USB autosuspend (`ID_AUTOSUSPEND=1`) between sessions.
- [ ] **Cold-boot login screen** (GDM through `pam_fprintd`).
- [ ] **Brush retry.** A touch under 180 ms is now a "too short" retry, not a no-match. Check on the lock screen
      that a quick brush asks again instead of falling back to the password. A deliberate brush lasted 424 ms
      and matched (Run 47), so this needs a real graze, under 180 ms.
- [x] **Match before the lift:** 103–115 ms after finger-down, and a reopen 37 ms later with the finger still on
      matched normally (Run 49).
- [x] **Re-image a held finger:** works on the EC (Run 51: three images ~120 ms apart, `finger up`, no warning).
      Still to see: a match on image 2 or 3. All three images of a resting finger were alike and scored 0.
- [ ] **Unlock screen after the PAM swap** (Run 51 installed it): the fingerprint prompt appears at once, also after
      resume, and no "Device was already claimed" shows in the journal.
- [x] **Faster open:** 498–506 ms, from ~965 ms (Runs 46–47, three opens, no warnings).
- [ ] Record the recovery behaviour of each in `docs/protocol.md`.

### Phase 6c — portability and upstreaming

- [ ] Derive the `0x98` DAC values and the FDT delta from the `0xa6` OTP reply, or restrict the driver to a
      per-device profile. Both are this unit's values today, and the OTP-derived DAC values must not be published.
- [ ] **PSK provisioning decision.** Dual-boot machines can unseal the key with `goodix-dpapi`. Linux-only machines
      have none, and the only known way to write one is `0xe0`, which overwrites Windows' key. Owning that path
      reverses this repo's no-destructive-opcodes rule, so it is a decision to make with upstream, after showing the
      device recovers.
- [ ] OpenCV is a new libfprint dependency (SIGFM). Upstream may want a different matcher or build option.
- [ ] Optional: reuse the TLS session across fprintd's close/open, if 1 s per prompt is still too slow.

### Phase 2 — publish (owner decision)

Both write-ups are drafted in [`docs/upstream-report.md`](docs/upstream-report.md); nothing has been posted.

- [ ] Work that file's **CHECK BEFORE POSTING** list (items 1, 2, 3, 7 are owner decisions, notably which identity
      posts).
- [ ] Post Draft A at [goodix-fp-dump][dump] and Draft B at the [libfprint tracker][issues]. Update both for the
      working driver first: they were written before Run 18.

**Never publish:** the PSK, its hash from the `0xe4` reply, `Goodix_Cache.bin`, the DPAPI master-key GUID, OTP
bytes, the OTP-derived `0x98` DAC values, templates, or any capture.

### Go reference — small offline follow-ups

- [ ] Harden the offline parsers: compare DPAPI master-key lengths before conversion to `int`
      (`internal/dpapi/dpapi.go`), bound key-stretch work, reject cyclic or deep registry subkey indexes
      (`internal/winreg/hive.go`), with malformed-input tests.
- [ ] Bound the Go bridge's writes and its background plaintext buffer, so cancellation and size limits apply
      while I/O is in progress.
- [ ] Make ordinary `--bisect` steps stop when their documented ACK or data reply is missing (keep `0x96`'s
      no-reply and the ACK-only commands).
- [ ] What the 8-byte header and 5-byte trailer around each frame hold.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[issues]: https://gitlab.freedesktop.org/libfprint/libfprint/-/issues
