# fprintd and PAM with the goodix5120 driver (owner only)

The system's own fprintd (Ubuntu `fprintd 1.94.5`) drives the reader through this driver's libfprint build, so
`fprintd-enroll`, `fprintd-verify` and `pam_fprintd` work (Runs 43–45 in `docs/protocol.md`). Agents do not run any
of it.

## How it is wired

`libfprint/goodix5120/fprintd/goodix5120-fprintd.sh` replaces no package. `install`:

- checks the bundle's `SHA256SUMS`;
- copies `dist/goodix-owner-c-sigfm-driver/libfprint/libfprint-2.so.2.0.0` to `/opt/goodix5120/lib`;
- copies the PSK from `captures/goodix-psk.bin` to `/etc/goodix5120/psk.bin` (root, `0600`). The repo's `captures/`
  is on a `fuseblk` mount, which ignores `chmod`;
- adds the drop-in `/etc/systemd/system/fprintd.service.d/goodix5120.conf`. It sets `LD_LIBRARY_PATH`, the PSK
  path, `FP_DRIVERS_ALLOWLIST=goodix5120` and milestone-level debug, and unsets `FP_DEBUG_TRANSFER`.

`BUNDLE=` and `PSK=` override the two source paths. fprintd keeps its own sandbox. The installed fprintd imports 47
libfprint symbols, and the pinned build (`1.94.100`, `6f9479c3`) exports all of them.

`uninstall` removes the library and the drop-in, so fprintd falls back to the distribution's libfprint, which does
not know this reader. It keeps `/etc/goodix5120/psk.bin` and the prints in `/var/lib/fprint`.

fprintd opens the reader per operation, so each prompt starts with the init and TLS handshake (about 1 s), then waits
for the touch.

## Install, enroll, verify

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
sudo "$repo/libfprint/goodix5120/fprintd/goodix5120-fprintd.sh" install
fprintd-enroll -f right-index-finger          # 15 touches; vary the placement a little each time
fprintd-verify -f right-index-finger
journalctl -b -u fprintd --since -15min -o cat --no-pager | grep -E 'open:|score|WARN|rror'
```

Rebuilding the bundle needs a re-run of `install`. Enrolling with varied placements matters: views that barely
overlap give a template that scores low on ordinary touches (Run 44).

To undo: `sudo "$repo/libfprint/goodix5120/fprintd/goodix5120-fprintd.sh" uninstall`. To drop the enrolled print
first: `fprintd-delete "$USER"`.

## PAM

`sudo pam-auth-update --enable fprintd` turns on Ubuntu's `pam_fprintd` profile: finger first, password as the
fallback. Undo it with `--disable fprintd`.

Ubuntu's profile is `pam_fprintd.so max-tries=1 timeout=10`, so one no-match goes straight to the password prompt
(Run 45). For more tries, change `max-tries` in `/usr/share/pam-configs/fprintd` and run `pam-auth-update` again.
That file belongs to the package, so an fprintd update can overwrite it.
