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

```sh
go build -buildvcs=false ./cmd/goodix-probe   # -buildvcs=false is used throughout the docs
go test ./...
go vet ./...
go test ./internal/transport -run TestReplayHappyPath   # single test
go test -tags goodix_destructive ./internal/proto   # tag-aware tests; cmd/goodix-probe safety tests intentionally fail under this tag

./goodix-probe --dry-run   # print the frames it would send; opens no USB device
./goodix-probe --replay    # full decode path against the scripted fake
./goodix-probe --bisect --replay --assume-keys   # bisect flow offline (no root, no USB)
```

## Architecture

The safety guarantee is structural, and changes must preserve it:

- **`internal/proto`** is pure (no I/O): two nested framings — pack `[flags][len LE16][checksum][payload]` wrapping message
  `[cmd][len LE16][payload][checksum]` — plus the opcode registry. Every opcode carries a `Class`: `ClassSafe` <
  `ClassStateChanging` < `ClassDestructive`. Registration happens only in `init()`.
- **Destructive opcodes are compiled out.** `write_firmware` (`0xf0`) and `preset_psk_write` (`0xe0`) are registered only in
  `opcode_destructive.go` behind the `goodix_destructive` build tag (`opcode_safe.go` is the default-build counterpart).
  Tests assert a default build cannot name them.
- **`internal/transport` is the single chokepoint.** Both the gousb transport (`usb.go`) and the replay fake (`replay.go`)
  embed `sender`, whose `Send` runs `checkOpcode` before any byte is written: unregistered opcodes are always refused,
  and any class above `Options.Ceiling` (zero value = `ClassSafe`) is refused. Refusals wrap `ErrRefused`. Don't add a
  write path that bypasses `sender`.
- **`cmd/goodix-probe`** runs a fixed `steps` sequence; `safety_test.go` fails if any step is not `ClassSafe` and checks
  the ceiling end to end through the replay transport.
- **`internal/tlspsk`, `internal/image`** are Tier 2 scaffolds with no call sites. TLS-PSK goes through an
  `openssl s_server` subprocess because Go's `crypto/tls` has no PSK suites (socket = ciphertext side, stdio = plaintext).

## Protocol divergences from upstream (handled in code)

The code was transcribed from goodix-fp-dump's `driver_51x0.py`; the device behaves differently:

- ACKs are a `0xb0` message with payload `[orig_cmd][status]` (`proto.AckCmd`, `proto.DecodeAck`), not `cmd | 0x01`.
  Keep this separate from the pack-layer `FlagTLSData` (`0xb0`). `AckCmd` is receive-only and must stay unregistered.
- Each command produces two transfers (ACK, then data). The probe's `collect` reads until data or `transport.ErrTimeout`,
  and `drain` empties the IN endpoint before exit. The replay transport is a FIFO that outlives each `Send`, like the
  device, so a caller that reads too little falls behind instead of losing data.
- The EC sends an unsolicited `0x32` message on attach; `read_otp` (`0xa6`) got no reply and is not in `steps`.
- `run1Script` is the Run 1 capture regrouped per command; don't add responses that were never observed.
