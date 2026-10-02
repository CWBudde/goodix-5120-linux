# fprintd with the goodix5120 driver (owner only)

Phase 6c's step after Runs 41–42: the system's own fprintd (Ubuntu `fprintd 1.94.5`) drives the reader through
this driver, so `fprintd-enroll` / `fprintd-verify` work, and after that PAM. Agents do not run any of it.

## How it is wired

`libfprint/goodix5120/fprintd/goodix5120-fprintd.sh` replaces no package. `install`:

- checks the bundle's `SHA256SUMS`;
- copies `dist/goodix-owner-c-sigfm-driver/libfprint/libfprint-2.so.2.0.0` to `/opt/goodix5120/lib`;
- copies the PSK to `/etc/goodix5120/psk.bin` (root, `0600`). The repo's `captures/` is on a `fuseblk` mount, which
  ignores `chmod`, so the permission warning only goes away with this copy;
- adds the drop-in `/etc/systemd/system/fprintd.service.d/goodix5120.conf`. It sets `LD_LIBRARY_PATH`, the PSK
  path, `FP_DRIVERS_ALLOWLIST=goodix5120` and milestone-level debug, and unsets `FP_DEBUG_TRANSFER`.

fprintd keeps its own sandbox. The installed fprintd imports 47 libfprint symbols, and the pinned build
(`1.94.100`, `6f9479c3`) exports all of them. With only the allowlisted driver, no other reader shows up.

`uninstall` removes the library and the drop-in, so fprintd falls back to the distribution's libfprint, which
does not know this reader. It keeps `/etc/goodix5120/psk.bin` and the prints in `/var/lib/fprint`.

fprintd opens the reader per operation, so each verify starts with the TLS handshake (about 3 s in Runs 41–42),
then waits for the touch.

## Run

```sh
repo=/mnt/Projekte/Code/systems/goodix-5120-linux
sudo "$repo/libfprint/goodix5120/fprintd/goodix5120-fprintd.sh" install
fprintd-list "$USER"                          # the reader, and no prints yet
fprintd-enroll -f right-index-finger          # 15 touches, lift after each
fprintd-verify -f right-index-finger          # once with the index, once with another finger
journalctl -b -u fprintd --since -15min -o cat   # the driver's milestones and scores
```

`fprintd-verify` uses the driver's **identify** when the device offers it, which it does. This is the first live
identify. Paste the terminal output and the `journalctl` lines, and say which finger each attempt used.

To undo: `sudo "$repo/libfprint/goodix5120/fprintd/goodix5120-fprintd.sh" uninstall`. To drop the enrolled
print first: `fprintd-delete "$USER"`.

## Next: PAM

Once fprintd verify works, `sudo pam-auth-update --enable fprintd` turns on the existing `pam_fprintd` profile
(fingerprint first, password as fallback). Try it with `sudo -k; sudo true` in a second terminal while the first
keeps a root shell open. Undo with `sudo pam-auth-update --disable fprintd`.
