# goodix-5120-linux

A Linux driver for the **Goodix `27c6:5120`** fingerprint reader in the Huawei MateBook `HVY-WXX9`, which no
distribution supports. The reader sits behind an **ITE embedded controller** (`GF_ITE_EC_20063`) that also drives the
internal keyboard, and it talks to the host over TLS-PSK.

**Status (2026-10-02): it works on this machine.** The libfprint driver in [`libfprint/goodix5120/`](libfprint/goodix5120/README.md)
enrolls (15 touches), verifies and identifies through the system's own fprintd, and `sudo` accepts the finger through
`pam_fprintd` (Runs 43–45 in [`docs/protocol.md`](docs/protocol.md)). An open takes about 1 s. Not yet tested live:
cancellation mid-open, suspend/resume, and the login screen after a cold boot ([`PLAN.md`](PLAN.md)).

> ## ⚠ The reader shares a chip with the keyboard
>
> A wrong frame has wedged the EC and killed the internal keyboard, and once an unfinished TLS handshake left it stuck
> through a normal cold power cycle. The fix that worked: shut down, **leave the charger plugged in, hold the power
> button 40 s** (`docs/protocol.md`, "Recovering the EC"). Keep a USB keyboard within reach until the remaining
> lifecycle tests have passed. Never run upstream `driver_51x0.main()` or any firmware-write path against this
> device. It would flash 5110 firmware onto an ITE EC.

## Install

**Requirements:**

- Ubuntu 26.04 on amd64. The prebuilt library links that release's glib, GUsb and OpenCV 4.10; on anything else,
  build it yourself (below).
- `fprintd` and `libpam-fprintd` installed (`sudo apt install fprintd libpam-fprintd`).
- A reader that reports firmware `GF_ITE_EC_20063`; the driver refuses anything else. Two init values (`0x98` DAC,
  FDT delta) are calibrated for the one tested unit. Another `HVY-WXX9` will probably need its own (`PLAN.md`).
- **The reader's PSK.** The EC only talks to a host that knows its 32-byte pre-shared key, which Windows provisioned
  and sealed with DPAPI. You need the Windows installation that set the reader up. A Linux-only machine has no way
  to get it yet ([PSK provisioning](libfprint/goodix5120/README.md#psk-provisioning-open-decision)).

### 1. Get the PSK from Windows

Mount the Windows partition read-only (if it is BitLocker-encrypted, unlock it first, e.g. with `dislocker`), then
unseal the key offline. Nothing is written to Windows and Windows Hello keeps working.

```sh
sudo mount -o ro /dev/nvme0n1p3 /mnt/windows        # your Windows partition
go build -buildvcs=false ./cmd/goodix-dpapi         # in a clone of this repository
w=/mnt/windows/Windows/System32
sudo ./goodix-dpapi -sys $w/config/SYSTEM -sec $w/config/SECURITY \
  -mkdir $w/Microsoft/Protect/S-1-5-18 \
  -blob /mnt/windows/ProgramData/Goodix/Goodix_Cache.bin -goodix -out psk.bin
```

`psk.bin` is the raw 32-byte key. Keep it private; it lets anyone talk to your reader. How the unseal works:
[`docs/protocol.md`](docs/protocol.md), "Unsealing the PSK offline".

### 2. Download and verify a release

```sh
gh release download --repo CWBudde/goodix-5120-linux --pattern 'goodix5120-*.tar.gz' --pattern SHA256SUMS
sha256sum -c SHA256SUMS
gh attestation verify goodix5120-*.tar.gz --repo CWBudde/goodix-5120-linux   # optional: built by this repo's CI
tar xzf goodix5120-*.tar.gz && cd goodix5120-*/
```

Or download both files from the [releases page](https://github.com/CWBudde/goodix-5120-linux/releases).

### 3. Install for fprintd, enroll, verify

```sh
sudo ./goodix5120-fprintd.sh install /path/to/psk.bin
fprintd-enroll -f right-index-finger     # 15 touches; lift after each and vary the placement a little
fprintd-verify -f right-index-finger
```

No package is replaced. The installer copies the library to `/opt/goodix5120/lib` and the key to
`/etc/goodix5120/psk.bin` (root, `0600`), and adds a systemd drop-in that makes fprintd load this library
([`docs/fprintd.md`](docs/fprintd.md)). To update, run `install` again from the new bundle; the key is kept.

### 4. Use it for sudo and login

```sh
sudo pam-auth-update --enable fprintd
```

Finger first, password as the fallback. Ubuntu's profile gives the finger one try (`max-tries=1`); one miss goes
straight to the password prompt. Each prompt starts with the reader's TLS handshake, about 1 s.

### Uninstall

```sh
fprintd-delete "$USER"                      # optional: remove your enrolled prints
sudo pam-auth-update --disable fprintd
sudo ./goodix5120-fprintd.sh uninstall      # fprintd falls back to the distribution's libfprint
```

`uninstall` keeps `/etc/goodix5120/psk.bin`; delete it by hand if you no longer need it.

### Build from source

```sh
just bundle                                 # docker; tests, then pinned libfprint with the driver
sudo libfprint/goodix5120/fprintd/goodix5120-fprintd.sh install /path/to/psk.bin
```

`just bundle` clones libfprint `6f9479c3` into `.cache/`, builds the Ubuntu 26.04 image from
`libfprint/goodix5120/build/`, and writes `dist/goodix5120-<version>/`; the installer picks the bundle in `dist/`.
To build into your own libfprint tree instead, see the [driver README](libfprint/goodix5120/README.md#building).

## Layout

```
libfprint/goodix5120/   the libfprint driver (C): protocol, TLS-PSK server, SIGFM matching, offline tests
  build/                the bundle build: Dockerfile and build-bundle.sh
  fprintd/              the reversible fprintd drop-in installer
cmd/goodix-probe/       Go reference implementation; --bisect is its only live mode (owner only)
cmd/goodix-dpapi/       unseals the PSK from a Windows partition, offline
cmd/goodix-pcap/        reads USBPcap captures of the Windows driver; never prints secrets
cmd/goodix-evtx/        reads the Windows driver's ETW debug log
internal/               framing, the send gate, transports, TLS-PSK, image decode, parsers
docs/protocol.md        the wire protocol and every live run, each fact marked transcribed or observed
docs/fprintd.md         installing for fprintd and PAM
docs/acpi.md            what the ACPI tables say about the EC, the keyboard and the port
docs/upstream-report.md drafts for goodix-fp-dump and libfprint, not posted yet
PLAN.md                 what is done and what is still open
```

## Safety by construction

The Go code and the C driver share the same rules, each enforced in code and pinned by tests:

- **One send gate.** Every frame goes through a single function that refuses unknown opcodes and payloads whose
  length differs from what the Windows driver sends. An argument-less `0xe4` wedged the EC three times. That frame
  can no longer be built.
- **No destructive opcodes.** `write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) are absent from the driver
  and compiled out of the Go binaries unless the `goodix_destructive` build tag is set.
- **Health check first.** Open sends `0xa8` and stops if the EC does not answer. A handshake that cannot succeed
  (missing PSK, OpenSSL policy without suite `0x00ae`) fails before the first USB byte.
- **Secrets stay out of logs.** The PSK, the `0xe4` reply (PSK hash), the `0xa6` reply (OTP), TLS application data
  and images are never logged. Captures, keys and templates live in gitignored `captures/` and never enter the repo.

## Development (offline, no device)

```sh
just check        # format check, golangci-lint + shellcheck, vet, Go tests (both opcode tags), C tests, tidy
just fmt          # treefmt: gofumpt, gci, prettier, shfmt, taplo, yamlfmt, just
just test-c       # C driver tests (fake USB, synthetic EC), normal and under ASan/UBSan
just rehearse     # Go: full TLS-PSK session against an in-process fake EC
just bundle       # the release bundle, in docker
```

Requirements: Go (see `go.mod`), `libusb-1.0-0-dev`, OpenSSL ≥ 3 headers and `pkg-config`. The C tests need
GLib/GIO, OpenSSL and meson; with OpenCV 4 the real SIGFM test runs too. Agents never run anything against the
device. Live tests are the owner's (see `AGENTS.md`).

CI runs the same checks on every push and pull request. Releases come from
[release-please](https://github.com/googleapis/release-please): merging its release PR tags `vX.Y.Z`, and the release
workflow attaches the built bundle, `SHA256SUMS` and a build provenance attestation. Commit messages follow
Conventional Commits (`feat:`, `fix:`, `docs:` …), which become the changelog.

## Credit

The protocol starts from [goodix-fp-linux-dev/goodix-fp-dump][dump] (which covers the 5120 only as an SPI part) and
its [libfprint fork][fork]. SIGFM, in `libfprint/goodix5120/sigfm/`, is vendored unmodified from the `goodixtls`
fork under LGPL-2.1+.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[fork]: https://github.com/goodix-fp-linux-dev/libfprint

## Licence

LGPL-2.1-or-later ([`LICENSE`](LICENSE)), the licence of libfprint and of the vendored SIGFM. A release bundle is a
modified libfprint and carries its sources in `source/`.
