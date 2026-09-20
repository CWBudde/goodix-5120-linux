# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Hardware safety — read first

This is bring-up work for the Goodix `27c6:5120` fingerprint reader in a Huawei MateBook (`HVY-WXX9`). The one live run
(2026-08-17) **wedged the ITE embedded controller and killed the internal keyboard**; only a cold power cycle (full
shutdown, charger unplugged, power button held ~30 s) recovered it. The device reports `GF_ITE_EC_20063`: it is an EC that
bridges to the sensor *and* drives the keyboard over i8042.

- **Never run the probe against live hardware** (`sudo ./goodix-probe`, no `--dry-run`/`--replay`), and never run upstream
  `driver_51x0.main()` or any IAP/firmware-write path. All verification is offline, against the replay transport.
- `FINDINGS.md` is the full account and recommendation; `PLAN.md` is the phased plan (Phase 1 = offline code fixes,
  Phase 4 live runs are gated on a vendor-driver USB capture); `docs/protocol.md` records the wire format, with each fact
  marked as transcribed from upstream or observed. Append new observations there.
- `--bisect` (`cmd/goodix-probe/bisect.go`, `host.go`) is the one sanctioned live mode, per
  `docs/bisect-runbook.md`. The **user** runs it with an external keyboard attached; Claude never does.
  Offline it runs as `--bisect --replay --assume-keys`.
- No firmware blobs (`*.bin`) or captures (`*.pgm`, `*.raw`, `captures/`) go into the repo — captures may contain
  biometric data.

## Commands

Requires `libusb-1.0-0-dev` (gousb is cgo).

The `justfile` wraps the offline ones (`just` lists them; `just check` is build + vet + both test
tags). It has no recipe that touches the device, on purpose — `just live-help` says why.

```sh
go build -buildvcs=false ./cmd/goodix-probe   # -buildvcs=false is used throughout the docs
go test ./...
go vet ./...
go test ./internal/transport -run TestReplayHappyPath   # single test
go test -tags goodix_destructive ./internal/proto ./internal/transport   # tag-aware tests; cmd/goodix-probe safety tests intentionally fail under this tag

./goodix-probe --dry-run   # print the frames it would send; opens no USB device
./goodix-probe --replay    # full decode path against the scripted fake
./goodix-probe --bisect --replay --assume-keys   # bisect flow offline (no root, no USB)

# The TLS-PSK bridge, rehearsed offline: no device is opened, and the "EC" is an
# openssl s_client in Goodix framing. Needs openssl on PATH.
./goodix-probe --bisect --replay --assume-keys --tls --psk captures/goodix-psk.bin \
  --allow-d0 --allow-d4 --allow-20 --steps a8 --capture /tmp/rehearsal.pgm
./goodix-probe --bisect --replay --assume-keys --tls --psk captures/goodix-psk.bin \
  --allow-d0 --steps a8 --rehearse-rejection   # what a PSK the EC rejects looks like

go build -buildvcs=false ./cmd/goodix-pcap
./goodix-pcap -in dump.pcapng                   # counts only, no payload bytes; reads a file, opens nothing
./goodix-pcap -in dump.pcapng -devices          # every device address in the capture: which hub, who kept transferring
go test ./internal/capture -capture "$PWD/dump.pcapng"   # checks the payload rules against real vendor traffic

go build -buildvcs=false ./cmd/goodix-evtx
./goodix-evtx -in log.evtx                      # summary only: counts, id range, span, message shapes; no record text
./goodix-evtx -in log.evtx -grep "Send data::0xa0e4"     # record text needs -grep or -text, and is bounded by -n
go test ./internal/evtx -log "$PWD/captures/Goodix-FingerprintProvider%4Debug.evtx"   # re-derives the 17545 / 18 / 9 figures
```

## Architecture

The safety guarantee is structural, and changes must preserve it:

- **`internal/proto`** is pure (no I/O): two nested framings — pack `[flags][len LE16][checksum][payload]` wrapping message
  `[cmd][len LE16][payload][checksum]` — plus the opcode registry. Every opcode carries a `Class`: `ClassSafe` <
  `ClassStateChanging` < `ClassDestructive`. Registration happens only in `init()`.
- **Destructive opcodes are compiled out.** `write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) are registered only in
  `opcode_destructive.go` behind the `goodix_destructive` build tag (`opcode_safe.go` is the default-build counterpart).
  Tests assert a default build cannot name them.
- **`internal/transport` is the single chokepoint.** The gousb transport (`usb.go`), the replay fake (`replay.go`)
  and the external-peer transport (`peer.go`) all
  embed `sender`, whose `Send` runs `check` before any byte is written: unregistered opcodes are always refused,
  any class above `Options.Ceiling` (zero value = `ClassSafe`) is refused unless `Options.Allow` names that exact
  opcode (never a destructive one), **and a payload that violates the opcode's registered `PayloadRule` is refused
  too** (class first, so a refusal names the worst reason). Refusals wrap `ErrRefused`; a payload refusal also wraps
  `proto.ErrPayload`. Don't add a write path that bypasses `sender`.
- **`SendTLS` is the one write with no opcode**, for the `0xb0` packs that carry TLS records to the device. There is
  no class to check, so the gate demands `Options.AllowTLSData` (off by default; only `--tls` sets it) and refuses
  anything that is not a whole number of TLS records — half a record is the same shape of mistake as an argument-less
  `0xe4`. `transport.NewPeer` exists so that a rehearsal richer than the scripted replay — one that really completes a
  handshake — still passes through the same gate instead of getting a private write path.
- **Every opcode needs a payload rule**, as a required argument to `register`. An empty-payload `0xe4` wedged the EC
  three times because nothing in the code knew it took an argument. `PayloadUnknown()` is the honest value for an
  opcode the vendor never sends; `TestPayloadRulesAreEvidenceBased` pins that set so it can only shrink.
- **`cmd/goodix-probe/vendor.go` is the single source of truth for payloads.** `vendorInit` is the driver's 14-frame
  init sequence; `steps` (one command, `a8 [00 00]`) is the subset cleared for live hardware. Growing `steps` is a
  Phase 4 decision, one command per run. `nop` is deliberately not a step.
- **`internal/capture` + `cmd/goodix-pcap`** read USBPcap captures offline. They may import `internal/proto` and
  nothing else from the repo — never `internal/transport`, never gousb — and purity tests parse the source to enforce
  it. `goodix-pcap` prints counts by default and refuses to print `0xe4` or `0xa6` payloads at all.
- The only `Allow` users are the `--bisect --allow-XX` flags, one per above-ceiling opcode, generated from the
  `unlockable` table in `bisect.go` — so an opcode cannot become sendable without a flag, and the flag's help text is
  where someone has to write down what the frame does and why it is safe enough to try.
  `TestEveryAboveCeilingVendorFrameIsCatalogued` pins that table against the vendor catalogue in both directions. A
  flag admits its opcode only when the run actually sends it (a `--steps` entry, or one of the commands `--tls` sends
  itself); the ceiling stays `ClassSafe` and no flag can admit a destructive opcode. `--allow-e4` sends the vendor's
  8-byte payload; the empty frame that wedged the EC is refused by the payload rule. See `docs/bisect-runbook.md`.
- **`cmd/goodix-probe`** runs a fixed `steps` sequence; `safety_test.go` fails if any step is not `ClassSafe` and checks
  the ceiling end to end through the replay transport.
- **`internal/tlspsk`, `internal/image`, `internal/session`** are the TLS-PSK image path. TLS-PSK goes through an
  `openssl s_server` subprocess because Go's `crypto/tls` has no PSK suites (socket = ciphertext side, stdio = plaintext).
  `internal/session` is the bridge between that and the device, **half duplex on purpose** so nothing writes to the
  OUT endpoint while something else reads from it. Their one caller is `goodix-probe --tls`, which runs as the tail of
  a bisect run and is therefore behind the same keyboard-safe procedure as any live step
  (`docs/bisect-runbook.md`, PLAN.md Phase 5b/5c).
- **A server flight goes to the device as ONE `0xb0` pack**, the way openssl writes it. Run 11 sent
  ServerHello and ServerHelloDone as two packs and the EC went silent without an alert; this is the response,
  and it is a **hypothesis, not a confirmed fact** — `--tls-record-per-pack` exists so the two can be
  compared on hardware, and `TestServerFlightGoesOutAsOnePack` stops the default drifting back silently.
  Records must be forwarded **verbatim**: the Finished MACs cover the handshake transcript, so a bridge that
  edits a record on the way past breaks the handshake it is trying to fix.
- **Handshake, change-cipher-spec and alert records are logged in full hex; application data never is.**
  The rule lives in one function (`proto.TLSRecord.PlaintextHex`) and is by record *type*, so it holds at
  every point in the session: those three types carry key agreement, a MAC or a reason code, never an image,
  and the PSK appears in none of them. `TestPlaintextHexNeverPrintsAnImage` pins the half that matters.
- **`session.LoopbackEC` is not a device and must never become one.** It is an `openssl s_client` in Goodix framing,
  used to rehearse the bridge offline; like the EC it stays silent until `0xd0`. It goes through
  `transport.NewPeer`, so a rehearsal refuses exactly what a live run refuses. `usb.go` remains the only code in the
  repository that opens hardware.

## Protocol divergences from upstream (handled in code)

The code was transcribed from goodix-fp-dump's `driver_51x0.py`; the device behaves differently:

- ACKs are a `0xb0` message with payload `[orig_cmd][status]` (`proto.AckCmd`, `proto.DecodeAck`), not `cmd | 0x01`.
  Keep this separate from the pack-layer `FlagTLSData` (`0xb0`). `AckCmd` is receive-only and must stay unregistered.
- Each command produces two transfers (ACK, then data). The probe's `collect` reads until data or `transport.ErrTimeout`,
  and `drain` empties the IN endpoint before exit. The replay transport is a FIFO that outlives each `Send`, like the
  device, so a caller that reads too little falls behind instead of losing data.
- The EC sends an unsolicited `0x32` message on attach; `read_otp` (`0xa6`) got no reply and is not in `steps`.
- `run1Script` is the Run 1 capture regrouped per command; don't add responses that were never observed.
