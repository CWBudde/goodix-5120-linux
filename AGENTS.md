# AGENTS.md

Guidance for coding agents working in this repository.

## What this is

A driver for the Goodix `27c6:5120` fingerprint reader in a Huawei MateBook (`HVY-WXX9`). The device reports
`GF_ITE_EC_20063`: an ITE embedded controller that bridges to the sensor over USB _and_ drives the internal keyboard
over i8042, and it talks to the host over TLS-PSK.

**State (2026-10-02):** the C libfprint driver in `libfprint/goodix5120/` works on this machine through the system
fprintd and `pam_fprintd` (Runs 43–45 in `docs/protocol.md`). It opens in about 965 ms, enrolls 15 touches and matches
with SIGFM (threshold 24; genuine scores so far 36–258594, other fingers 0–9). Not yet tested live: cancellation during
open, suspend/resume, autosuspend, cold-boot login. The Go code is the offline reference the driver follows byte for
byte. `PLAN.md` lists what is open.

## Hardware safety — read first

Wrong frames have **wedged the EC and killed the internal keyboard** (Runs 1, 2, 4, 12).

- **Agents never touch the device.** The owner runs every live tool: `goodix-probe` without `--dry-run`/`--replay`,
  libfprint's examples, the `fprintd-*` tools, `sudo` through PAM, `pam-auth-update`, and
  `libfprint/goodix5120/fprintd/goodix5120-fprintd.sh`. Never run upstream `driver_51x0.main()` or any
  IAP/firmware-write path. All verification is offline (replay transport, fake-USB driver tests).
- **An unfinished TLS handshake leaves the EC stuck**, answering nothing but `0xae`, and a normal cold power cycle did
  not clear it (Run 14). What did (Run 16): shut down with the charger **plugged in**, hold the power button **40 s**
  (`docs/protocol.md`, "Recovering the EC"). Do not boot Windows while it is stuck: its driver re-sends the init.
- **Never commit** firmware blobs (`*.bin`), captures (`*.pgm`, `*.raw`, `*.pcapng`, `captures/`), templates, or logs
  with biometric data. **Never print or publish** the PSK, the `0xe4` reply (PSK hash), the `0xa6` reply (OTP), the
  OTP-derived `0x98` DAC values, the DPAPI boot key or master-key GUID. The PSK lives in gitignored
  `captures/goodix-psk.bin` and, installed, in `/etc/goodix5120/psk.bin`.

## Live-testing workflow

- The agent builds offline and hands the owner short command blocks; the owner runs them and pastes the output.
  No separate health check or keyboard report since Run 41: open does its own `0xa8` health check.
- Record each run in `docs/protocol.md` as the next "### Run N — date, title (observed)" section, inserted before
  "### Recovering the EC", with the owner's own description of what they did. Update `PLAN.md`'s open list. Commit.
- The default driver log is milestones only (`open: N ms`, TLS up, finger down/up, keypoints, `best SIGFM score N`,
  warnings). Wire detail needs `GOODIX5120_TRACE=1`. Leave `FP_DEBUG_TRANSFER` unset: libfprint's transfer dump
  bypasses the driver's redaction. Under fprintd:
  `journalctl -b -u fprintd --since -15min -o cat --no-pager | grep -E 'open:|score|WARN|rror'`.
- Ubuntu's PAM profile is `pam_fprintd.so max-tries=1 timeout=10`: one no-match falls back to the password. That is
  configuration, not a driver failure.

## Layout

- `libfprint/goodix5120/`: the driver. `goodix5120.c` (`FpiSsm` state machines, USB), `goodix5120_proto.c` (pure
  framing, send gate, vendor sequence, FDT thresholds, 12-bit unpacking), `goodix5120_tls.c` (TLS 1.2 PSK server on
  OpenSSL memory BIOs), `goodix5120_match.c` + `goodix5120_sigfm.cpp` (validated template, SIGFM backend), `sigfm/`
  (vendored unmodified, LGPL-2.1+), `tests/` (fake libfprint/USB adapter, synthetic EC), `libfprint-register.patch`,
  `fprintd/goodix5120-fprintd.sh` (reversible fprintd drop-in). Its README holds the timing and logging rules.
- `cmd/goodix-probe/`: Go reference; `--bisect` is its only live mode. `cmd/goodix-dpapi/`: unseals the PSK from a
  Windows partition offline. `cmd/goodix-pcap/`, `cmd/goodix-evtx/`: read the Windows driver's USB captures and ETW log.
- `internal/`: framing and opcode registry (`proto`), the send gate (`transport`), TLS-PSK (`tlspsk`, `session`),
  image decode (`image`), offline parsers (`capture`, `evtx`, `dpapi`, `winreg`), shared Go/C fixtures (`testfixtures`).
- `docs/protocol.md`: wire format and every run, each fact marked transcribed (from upstream) or observed.
  `docs/fprintd.md`: what the fprintd installer changes. `docs/acpi.md`: firmware tables. `docs/upstream-report.md`: unposted drafts.
  `PLAN.md`: open work.

## Commands (offline)

Requires Go (see `go.mod`), `libusb-1.0-0-dev`, OpenSSL ≥ 3 headers and `pkg-config` (gousb and TLS are cgo). If cgo
test links fail in `/tmp`, set `GOTMPDIR` to a directory on another filesystem. The `justfile` has no recipe that
touches the device, on purpose (`just live-help`).

```sh
just check                                    # fmt-check, lint, vet, Go tests (both tags), C tests, build, tidy
just fmt                                      # treefmt: gofumpt, gci, prettier, shfmt, taplo, yamlfmt, just
just lint                                     # golangci-lint (.golangci.toml) + shellcheck
go test -race ./...
go test ./internal/transport -run TestReplayHappyPath   # single test
go test -tags goodix_destructive ./internal/proto ./internal/transport   # cmd/goodix-probe safety tests fail under this tag, on purpose

just dry-run                                  # frames the probe would send; opens no USB device
just bisect-offline                           # --bisect --replay
just rehearse                                 # full TLS-PSK session against an in-process fake EC, synthetic keys

# The C driver: the real goodix5120.c against a fake libfprint/USB adapter and a synthetic EC
just test-c                                   # normal, then ASan/UBSan (builds in /tmp/g5120, /tmp/g5120-asan)
/tmp/g5120/test-goodix5120-driver -p /goodix5120/driver/enroll/complete   # one scenario

./goodix-pcap -in dump.pcapng                 # counts only; refuses to print 0xe4/0xa6 payloads
./goodix-evtx -in log.evtx -grep "Send data::0xa0e4"   # record text needs -grep or -text
```

`just bundle` is the full build: `libfprint/goodix5120/build/build-bundle.sh` runs in the Ubuntu 26.04 image from
that directory's `Dockerfile`, with `--network none`, against pinned libfprint `6f9479c3` (cloned into `.cache/`).
It runs the C tests, builds libfprint with `libfprint-register.patch` and the driver, refuses driver warnings, and
writes `dist/goodix5120-<version>/` (library, examples, installer, `source/`, `SHA256SUMS`). The fprintd installer
picks that bundle up; the owner re-runs `install` after a rebuild.

**CI and releases.** `.github/workflows/tests.yaml` runs Go tests, lint, the format check and the bundle build on
every push and PR. release-please keeps a release PR from the conventional commits; merging it tags `vX.Y.Z`, and
`release.yaml` attaches the bundle tarball, `SHA256SUMS` and a provenance attestation. Formatter versions are pinned
in `test-format.yaml`; keep them in step with the local tools.

## Architecture: safety is structural

Changes must preserve these; each is pinned by tests.

**Both implementations**

- **One send gate.** Go: `internal/transport`'s `sender.Send` runs `check` before any byte is written. C:
  `g5120_command_frame()`. Unregistered opcodes are refused, and so is any payload whose length differs from the
  opcode's registered rule. An argument-less `0xe4` wedged the EC three times; it cannot be built. Don't add a write
  path around the gate.
- **No destructive opcodes.** `write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) are absent from the C driver
  and registered in Go only behind the `goodix_destructive` build tag (`opcode_destructive.go` / `opcode_safe.go`).
- **Health check first.** Open sends `0xa8` and stops unless it answers `GF_ITE_EC_20063`. `0xae` cannot be the probe:
  it is the one command a stuck EC still answers. A handshake that cannot succeed (missing or malformed PSK, OpenSSL
  policy without suite `0x00ae`) fails before USB is claimed.
- **Half duplex.** Nothing writes to OUT while a reply is awaited.
- **TLS records are forwarded verbatim, one `0xb0` pack per record**, and the host keeps reading the EC until its
  flight (ClientKeyExchange, ChangeCipherSpec, Finished: three transfers) is complete (Runs 11, 17, 18).
- **TLS pacing.** No two host writes closer than 10 ms: 60 ms between ServerHello/ServerHelloDone and between
  ChangeCipherSpec/Finished, 10 ms settle before `0xd4`, 50 ms listen after its ACK. Sub-millisecond write pairs made
  the EC reject the session or never set its TLS bit (Runs 24–33).
- **Redaction.** Handshake, change-cipher-spec and alert records may be logged in full (Go:
  `proto.TLSRecord.PlaintextHex`, by record type); application data, images, the PSK and the `0xe4`/`0xa6` replies
  never. Go's one deny list is `proto.SecretReply` / `proto.SecretPack`; print received transfers through
  `rawdump`/`dumpRX`, never plain `hexdump`/`dump`.
- **Shared fixtures.** Go and C check the 14 init payloads, every config byte, reply expectations, FDT vectors and
  images against one corpus in `internal/testfixtures/testdata/`.

**C driver**

- A plain `FpDevice`, not an image device: NBIS finds at most 5 minutiae on 64 × 80 (Run 37) and Bozorth3 needs 10.
  Own enroll (15 stages) / verify / identify / capture. Frames are 12-bit, contrast-stretched (1st/99th percentile),
  enlarged ×3 to 192 × 240 with pixman, then SIGFM. libfprint's heat model is off (`temp_hot_seconds = -1`).
- Stored templates (`(yqqa(a(qq)ay))`, about 200 KB, biometric) are validated in full before SIGFM sees them.
- Fail closed: a missing or early reply, an ACK status other than `0x01`, a stalled handshake stops the sequence.
  After an image/TLS/transport failure the session is discarded until close/reopen. Every touch waits for finger-up
  before the action reports. Close sends nothing; no USB reset.
- Only the attach drain waits 200 ms; drains between open steps wait 20 ms.
- `0x98` DAC values and `fdt_delta` (27) are this unit's; deriving them from OTP is open.

**Go reference**

- `internal/proto` is pure (no I/O): pack `[flags][len LE16][checksum][payload]` wrapping message
  `[cmd][len LE16][payload][checksum]`, plus the opcode registry. Every opcode has a `Class` (`ClassSafe` <
  `ClassStateChanging` < `ClassDestructive`) and a required `PayloadRule`; registration only in `init()`.
  `PayloadUnknown()` is for opcodes the vendor never sends; `TestPayloadRulesAreEvidenceBased` lets that set only shrink.
- The gate refuses any class above `Options.Ceiling` (zero value `ClassSafe`) unless `Options.Allow` names that exact,
  non-destructive opcode. The only `Allow` users are the `--bisect --allow-XX` flags, generated from the `unlockable`
  table in `bisect.go`, whose help text says what each frame does; `TestEveryAboveCeilingVendorFrameIsCatalogued` pins
  it. A flag admits its opcode only when the run sends it.
- `SendTLS` is the one write with no opcode: it needs `Options.AllowTLSData` (only `--tls` sets it) and whole TLS
  records only.
- `cmd/goodix-probe/vendor.go` is the single source of truth for payloads: `vendorInit` (14 frames) and `steps`
  (`a8` only, the default). `nop` is deliberately not a step. `safety_test.go` checks the ceiling end to end.
- TLS-PSK runs in process on OpenSSL memory BIOs (Go's `crypto/tls` has no PSK suites): no subprocess, no listener.
  `session.LoopbackEC` is an in-process OpenSSL client in Goodix framing for rehearsals; it goes through
  `transport.NewPeer` and must never become a device. `usb.go` is the only code that opens hardware.
- `internal/capture` and `cmd/goodix-pcap` may import `internal/proto` and nothing else from the repo (never
  `transport`, never gousb); purity tests parse the source.
- `--bisect` sends `0xa8` after attach (`checkECResponsive`) and refuses to send a step if nothing answers;
  `--read-state` adds one `0xae` after a failed check and nothing else.

## Protocol divergences from upstream goodix-fp-dump

- ACKs are a `0xb0` message `[orig_cmd][status]` (`proto.AckCmd`, receive-only, unregistered), not `cmd | 0x01`. Keep
  it separate from the pack-layer `FlagTLSData` (`0xb0`).
- Each command produces two transfers, ACK then data. `0x96` draws no reply; `0x70` and `0xd4` draw an ACK only;
  `0xae` draws data only. The replay transport is a FIFO that outlives each `Send`, like the device.
- The EC sends an unsolicited `0x32` on attach (a stale finger event from Windows' last arm).
- The sensor is 64 columns × 80 rows; a frame decrypts to 7693 bytes (8-byte header, 7680 samples, 5-byte trailer).
- The PSK is sealed per machine with DPAPI plus derived entropy, not the upstream zero key (`docs/protocol.md`,
  "Unsealing the PSK offline").
- `run1Script` is the Run 1 capture regrouped per command; don't add responses that were never observed.

## Style, tests, commits

- Run `just fmt` and `just lint` before committing; CI fails on either. Go: idiomatic, gofumpt + gci. C: libfprint/GLib style, two-space indent,
  snake_case, `g5120_` helpers. Match the surrounding comment density.
- Docs: distinguish observed from transcribed or inferred; short, plain sentences.
- Add a synthetic regression test for each behaviour change; keep the safety tests. Report fixture-dependent skips.
- Commits follow Conventional Commits (`feat(scope):`, `fix(scope):`, `perf:`, `build:`, `docs:`, `test:`, `ci:`,
  `style:`, `chore:`); release-please turns them into the version bump and the changelog. Sanitize logs; keep private
  captures out of diffs.
