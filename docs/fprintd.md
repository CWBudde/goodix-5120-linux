# How the fprintd install works

The install steps are in the [README](../README.md#install). This page describes what
`goodix5120-fprintd.sh` changes on the system. Only the owner runs it, never an agent.

## What `install` does

The script replaces no package. It works from an extracted release bundle (the script sits at the bundle's root) or
from the repository, where it picks the newest bundle that `just bundle` left in `dist/`: the one whose `SHA256SUMS`,
the file the build writes last, has the latest modification time. The directory names end in a commit hash, so
their alphabetical order says nothing about age. `BUNDLE=` overrides both. `install` prints the bundle's path and its
`VERSION`, and `goodix5120-fprintd.sh which-bundle` prints the pick without root and without changing anything.

- checks the bundle's `SHA256SUMS`;
- copies `libfprint/libfprint-2.so.2.0.0` to `/opt/goodix5120/lib`;
- copies the PSK (`install PSK_FILE`, else `PSK=`, else the repo's `captures/goodix-psk.bin`) to
  `/etc/goodix5120/psk.bin` (root, `0600`). A re-install without a key keeps the installed one;
- writes the drop-in `/etc/systemd/system/fprintd.service.d/goodix5120.conf`. It sets `LD_LIBRARY_PATH`, the PSK
  path, `FP_DRIVERS_ALLOWLIST=goodix5120` and milestone-level debug, and unsets `FP_DEBUG_TRANSFER`, whose raw transfer
  dumps would bypass the driver's redaction. It also runs fprintd with `--no-timeout` (see "fprintd stays running"
  below). `goodix5120-fprintd.sh dropin` prints the drop-in without root;
- copies the PAM profile `goodix5120-fprintd` to `/usr/share/pam-configs/`, replacing the one a previous install left.
  If fingerprint login is enabled in PAM (`pam_fprintd` in `common-auth`), it replaces pam-auth-update's `fprintd`
  profile with this one. It has `pam_fprintd` with `max-tries=3` instead of Ubuntu's 1, and skips it for the
  `gdm-password` service. GNOME's unlock screen runs `gdm-password` and `gdm-fingerprint` side by side. With
  `pam_fprintd` in both, they race for the reader, and when `gdm-password` wins, the password prompt is blocked until
  `pam_fprintd` gives up after 10 s ("Zeitüberschreitung", Run 50). Afterwards the finger on the GNOME screens goes
  through `gdm-fingerprint` alone, as on Fedora, whose `gdm-password` has no `pam_fprintd` either. `sudo`, polkit and
  the TTY login are unchanged;
- stops fprintd, which D-Bus starts again on first use with the new library.

A re-install regenerates `common-auth` from the new profile: `pam-auth-update` rebuilds the managed block from the
enabled profiles' current files and keeps only edits made by hand in `common-auth`. Rehearsed with
`pam-auth-update --root` on a copy of this machine's PAM files, with the old `max-tries=1` profile enabled: only the
`pam_fprintd` line in `common-auth` changed, to `max-tries=3`.

fprintd keeps its own sandbox. Ubuntu's fprintd 1.94.5 imports 47 libfprint symbols, and the pinned build
(`1.94.100`, `6f9479c3`) exports all of them. With only the allowlisted driver, no other reader shows up.

`uninstall` swaps the stock `fprintd` PAM profile back (if `install` swapped it) and removes the library and the
drop-in, so fprintd falls back to the distribution's libfprint, which does not know this reader, and to the stock
`ExecStart` with its idle exit. It stops fprintd, so the long-running instance does not keep the old library. It keeps
`/etc/goodix5120/psk.bin` and the prints in `/var/lib/fprint`.

## fprintd stays running

By default fprintd exits after 30 s without a client, and D-Bus starts it again for the next prompt. In the journal,
"Starting fprintd" to "Started" took 170–240 ms on each prompt (service start and library loading), on top of the
reader's own open. The drop-in removes that: it clears the stock `ExecStart=` and starts the same command with
`--no-timeout` ("Do not exit after unused for a while", from `fprintd --help` of the installed 1.94.5). fprintd is still
started by D-Bus on first use after boot, then stays. The reader is still opened per operation, so it is idle and
closed between prompts.

The installer takes the command from the installed unit file, not a fixed path. It leaves `ExecStart` alone, and prints
a note, if that unit has no single plain `ExecStart=/path` line, or if the binary does not contain the flag. Then
fprintd keeps its idle exit and everything else works as before.

Not tested live yet: a long-running fprintd across suspend/resume. Run 50 showed the reader comes back after a resume,
but there fprintd had been started fresh after it.

## Behaviour under fprintd

- fprintd opens the reader per operation, so each prompt starts with the init and TLS handshake (about 500 ms, Run 46),
  then waits for the touch.
- Enroll takes 15 touches. Views that barely overlap make a template that scores low on ordinary touches (Run 44), so
  vary the placement a little between touches.
- The PAM profile is `pam_fprintd.so max-tries=3 timeout=10`. Ubuntu's stock profile has `max-tries=1`, where one
  no-match went straight to the password prompt (Run 45), and genuine scores are sometimes marginal (33 against the
  threshold of 24). To change it, edit `goodix5120-fprintd.pam-config` next to the script and run `install` again. The
  active profile is `/usr/share/pam-configs/goodix5120-fprintd`, which `install` overwrites each time, so edits there do
  not last.
- A fingerprint login cannot unlock the GNOME login keyring: `pam_gnome_keyring` needs the password. The journal shows
  `gkr-pam: no password is available for user` on each finger unlock. So after a cold-boot login by finger, the keyring
  asks for the password on its first use.
- A match is reported as soon as the image has been scored, about 115 ms after finger-down, without waiting for the
  finger to lift. Before this, the result came at the lift, 0.4–1.6 s after finger-down in Runs 46–47.
- A touch that does not match is imaged again while the finger stays on, up to three images, as the Windows driver
  does. So if a touch fails, leaving the finger on gives it two more chances. Only after the third image, or once the
  finger has gone, is it a no-match.
- A touch that did not match and left the sensor less than 180 ms after finger-down is a brush, not a scan: the image was taken
  while the finger landed or lifted. The driver reports it as "too short" (a retry) instead of a no-match. fprintd
  then waits for another touch, which should not use up `max-tries` (expected from fprintd's retry handling, not yet
  tested live). Observed before the change: a 144 ms lock-screen brush scored 0 and fell back to the password; the
  shortest genuine touch in the journal was 203 ms.

## Passkeys in the browser

The reader does not show up as a passkey (WebAuthn) option, and this driver cannot change that. Chrome and Firefox on
Linux have no platform authenticator and do not talk to fprintd. What should work with this setup is a password manager
that stores passkeys and unlocks through polkit: polkit authenticates through `common-auth`, and so through
`pam_fprintd`. Not tested on this machine.

## Logs

```sh
journalctl -b -u fprintd --since -15min -o cat --no-pager | grep -E 'open:|score|WARN|rror'
```

The default log has milestones only: `open: N ms`, TLS up, finger down, keypoints,
`best SIGFM score N, threshold 24` per image, `finger still on … image N of 3` before another image, then
`match on image N, N ms after finger-down` or `finger up after N ms`, warnings. For wire-level detail, add `Environment=GOODIX5120_TRACE=1` to the drop-in. Keys, OTP, images and
templates are never logged at either level.
