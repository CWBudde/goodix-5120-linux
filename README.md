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

## Using it

1. **The PSK.** The EC only talks to a host that knows its 32-byte pre-shared key, which Windows provisioned and sealed
   with DPAPI. On a dual-boot machine, `goodix-dpapi` unseals it offline from the Windows partition
   ([`docs/protocol.md`](docs/protocol.md), "Unsealing the PSK offline"). A Linux-only machine has no way to get it
   yet ([PSK provisioning](libfprint/goodix5120/README.md#psk-provisioning-open-decision)).
2. **The library.** Build libfprint with this driver ([driver README](libfprint/goodix5120/README.md#building)).
3. **fprintd.** `libfprint/goodix5120/fprintd/goodix5120-fprintd.sh install` points the system fprintd at that build
   with a systemd drop-in. It replaces no package and `uninstall` undoes it. See [`docs/fprintd.md`](docs/fprintd.md).

The driver refuses any firmware other than `GF_ITE_EC_20063`, and two of its init values (`0x98` DAC, FDT delta) are
calibrated for this one unit. It is not yet known how to derive them for another machine.

## Layout

```
libfprint/goodix5120/   the libfprint driver (C): protocol, TLS-PSK server, SIGFM matching, offline tests
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
FINDINGS.md             the account of the first live run (2026-08-17) and the keyboard incident
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
just check                                    # Go: build, vet, tests under both opcode tags
meson setup build-c libfprint/goodix5120 && meson test -C build-c   # C driver tests (fake USB, synthetic EC)
just rehearse                                 # Go: full TLS-PSK session against an in-process fake EC
```

Requirements: Go (see `go.mod`), `libusb-1.0-0-dev`, OpenSSL ≥ 3 headers and `pkg-config`. The C tests need
GLib/GIO and OpenSSL headers; with OpenCV 4 the real SIGFM test runs too. Agents never run anything against the
device. Live tests are the owner's (see `AGENTS.md`).

## Credit

The protocol starts from [goodix-fp-linux-dev/goodix-fp-dump][dump] (which covers the 5120 only as an SPI part) and
its [libfprint fork][fork]. SIGFM, in `libfprint/goodix5120/sigfm/`, is vendored unmodified from the `goodixtls`
fork under LGPL-2.1+.

[dump]: https://github.com/goodix-fp-linux-dev/goodix-fp-dump
[fork]: https://github.com/goodix-fp-linux-dev/libfprint

## Licence

Not yet chosen. Vendored SIGFM is LGPL-2.1+. Upstream goodix-fp-dump is GPL-licensed, which constrains the choice
if code is ported rather than reimplemented from the protocol description.
