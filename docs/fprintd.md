# How the fprintd install works

The install steps are in the [README](../README.md#install). This page describes what
`goodix5120-fprintd.sh` changes on the system. Only the owner runs it, never an agent.

## What `install` does

The script replaces no package. It works from an extracted release bundle (the script sits at the bundle's root) or
from the repository, where it picks the bundle that `just bundle` left in `dist/`. `BUNDLE=` overrides both.

- checks the bundle's `SHA256SUMS`;
- copies `libfprint/libfprint-2.so.2.0.0` to `/opt/goodix5120/lib`;
- copies the PSK (`install PSK_FILE`, else `PSK=`, else the repo's `captures/goodix-psk.bin`) to
  `/etc/goodix5120/psk.bin` (root, `0600`). A re-install without a key keeps the installed one;
- writes the drop-in `/etc/systemd/system/fprintd.service.d/goodix5120.conf`. It sets `LD_LIBRARY_PATH`, the PSK
  path, `FP_DRIVERS_ALLOWLIST=goodix5120` and milestone-level debug, and unsets `FP_DEBUG_TRANSFER`, whose raw transfer
  dumps would bypass the driver's redaction;
- stops fprintd, which D-Bus starts again on first use with the new library.

fprintd keeps its own sandbox. Ubuntu's fprintd 1.94.5 imports 47 libfprint symbols, and the pinned build
(`1.94.100`, `6f9479c3`) exports all of them. With only the allowlisted driver, no other reader shows up.

`uninstall` removes the library and the drop-in, so fprintd falls back to the distribution's libfprint, which does
not know this reader. It keeps `/etc/goodix5120/psk.bin` and the prints in `/var/lib/fprint`.

## Behaviour under fprintd

- fprintd opens the reader per operation, so each prompt starts with the init and TLS handshake (about 500 ms, Run 46),
  then waits for the touch.
- Enroll takes 15 touches. Views that barely overlap make a template that scores low on ordinary touches (Run 44), so
  vary the placement a little between touches.
- Ubuntu's PAM profile is `pam_fprintd.so max-tries=1 timeout=10`. One no-match goes straight to the password prompt
  (Run 45). For more tries, change `max-tries` in `/usr/share/pam-configs/fprintd` and run `pam-auth-update` again.
  That file belongs to the package, so an fprintd update can overwrite it.
- A match is reported as soon as the image has been scored, about 115 ms after finger-down, without waiting for the
  finger to lift. Before this, the result came at the lift, 0.4–1.6 s after finger-down in Runs 46–47. A no-match
  still waits for the lift.
- A touch that did not match and left the sensor less than 180 ms after finger-down is a brush, not a scan: the image was taken
  while the finger landed or lifted. The driver reports it as "too short" (a retry) instead of a no-match. fprintd
  then waits for another touch, which should not use up `max-tries` (expected from fprintd's retry handling, not yet
  tested live). Observed before the change: a 144 ms lock-screen brush scored 0 and fell back to the password; the
  shortest genuine touch in the journal was 203 ms.

## Logs

```sh
journalctl -b -u fprintd --since -15min -o cat --no-pager | grep -E 'open:|score|WARN|rror'
```

The default log has milestones only: `open: N ms`, TLS up, finger down, keypoints,
`best SIGFM score N, threshold 24`, then `match N ms after finger-down` or `finger up after N ms`, warnings. For wire-level detail, add `Environment=GOODIX5120_TRACE=1` to the drop-in. Keys, OTP, images and
templates are never logged at either level.
