# Plan: `27c6:5120`

**This file is the plan, not the record.** Every run and finding is in [`docs/protocol.md`](docs/protocol.md),
the first incident included (Run 1). The step-by-step history of this file is in git.

Standing rules: the owner runs everything live, never Claude. Never run upstream `driver_51x0.main()` or any IAP /
firmware-write path. `write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) stay out of every default build.

## Where we stand (2026-11-13)

**The reader works on Linux, end to end, through fprintd and PAM** (Runs 45–52). The C driver in
[`libfprint/goodix5120/`](libfprint/goodix5120/README.md) opens in about 500 ms (498–512 ms since Run 46), enrolls 15 touches, and matches
with SIGFM (threshold 24). Genuine scores so far are 33–258594 (the 33 was a live unlock on 2026-11-07, from the
fprintd journal), other fingers 0–9.

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
| 6, integration — fprintd drop-in, PAM, 1 s open (500 ms from Run 46)          | `sudo` by finger                                    | 42–45 |
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

### Phase 6c — unlock-prompt latency and daily use

Observed in the fprintd journal, 2026-11-07 to 2026-11-12 (read 2026-11-12), unlock prompts with the finger already on
the sensor: D-Bus activation to "Started fprintd" about 190 ms (170–240 ms); "Started" to the driver's first open line
140–735 ms (owned by fprintd and GDM, cause not identified); open 494–512 ms; finger-down to match 108–124 ms. So the
sensor is armed 0.9–1.4 s after the prompt appears.

- [x] **Keep fprintd running.** The installer's drop-in adds `--no-timeout`; fprintd stayed up 65 s and served a
      second prompt without a restart (Run 52). Still to check: a long-lived fprintd across suspend/resume, and the
      time from prompt to open on the unlock screen with fprintd already running.
- [ ] **Reuse the TLS session (open, undecided).** It is the largest remaining lever: most of the ~500 ms open is
      init and handshake. Sketch: keep the TLS state on close; on reopen send the `0xa8` health check and the `0xae`
      state check, then arm; fall back to the full init and handshake on any doubt. The vendor driver short-circuits
      on `isTlsConnected` on resume (`docs/protocol.md`). Unknown: whether the EC keeps the session keys across a USB
      interface release or autosuspend. Needs owner-run live tests, and only pays when fprintd stays running. Do not
      trim the TLS pacing instead (Runs 24–33).
- [ ] **Prompts with no finger-down (owner question).** In 6 of 17 unlock prompts in that period the reader opened,
      no finger-down was logged, and the password was typed a few seconds later (for example 2026-11-08 14:49,
      2026-11-10 22:54, 2026-11-12 11:15). Was a finger on the sensor? If yes, this is a missed finger-down to
      investigate; if the owner simply typed, it is nothing.
- [ ] **PAM `max-tries=3`.** One genuine match scored 33 against the threshold of 24 (2026-11-07 19:39), the lowest
      genuine score seen. The profile with three tries is installed (Run 52). Still to see: a second or third try
      after a no-match in `sudo` or polkit, and whether a "too short" brush uses up a try.
- [x] **Installer bundle choice.** The installer took its bundle from `dist/` in glob (hash) order, which could
      select an older build. It now takes the newest by date and prints it (Run 52: `6bfc625`, not `c8e7570`).
- Browser passkeys are not a driver item: Linux browsers have no platform authenticator that talks to fprintd. See
  [`docs/fprintd.md`](docs/fprintd.md).

### Phase 6c — portability and upstreaming

- [ ] Derive the `0x98` DAC values and the FDT delta from the `0xa6` OTP reply, or restrict the driver to a
      per-device profile. Both are this unit's values today, and the OTP-derived DAC values must not be published.
- [ ] **PSK provisioning decision.** Dual-boot machines can unseal the key with `goodix-dpapi`. Linux-only machines
      have none, and the only known way to write one is `0xe0`, which overwrites Windows' key. Owning that path
      reverses this repo's no-destructive-opcodes rule, so it is a decision to make with upstream, after showing the
      device recovers.
- [ ] OpenCV is a new libfprint dependency (SIGFM). Upstream may want a different matcher or build option.

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
