# Repository Guidelines

## Project Structure & Module Organization

- `cmd/`: Go commands for probing, USB capture analysis, Windows event logs, and DPAPI unsealing.
- `internal/`: protocol, gated transports, TLS sessions, image decoding, and offline parsers. Go tests sit beside source as `*_test.go`.
- `libfprint/goodix5120/`: experimental C image driver, protocol/TLS helpers, GLib tests in `tests/`, and libfprint registration patch.
- `docs/`: protocol evidence and runbooks. `FINDINGS.md` records findings; `PLAN.md` tracks work.
- `captures/`: ignored local secrets and biometric artifacts; never commit them.

## Hardware Safety & Architecture

Read `CLAUDE.md`, `FINDINGS.md`, and the relevant runbook before changing device communication. The ITE controller also drives the keyboard; incorrect commands have disabled it.

Agents must verify offline and never access live hardware. Owner-run experiments require the external-keyboard procedure in `docs/bisect-runbook.md`; C-driver experiments also follow its README and the review gate in `PLAN.md`.

Preserve opcode/payload gates, half-duplex exchanges, secret redaction, and destructive opcodes being excluded from default builds. Keep offline parsers independent of USB transports. Never publish PSKs, boot keys, OTP data, firmware blobs, or biometric captures.

## Build, Test, and Development Commands

Go builds require the version specified in `go.mod` and libusb development headers. TLS rehearsals require OpenSSL.

- `just build`: build all Go commands.
- `just check`: build, vet, test both supported tag configurations, and list formatting differences.
- `go test -race ./...`: check Go concurrency.
- `just dry-run` or `just bisect-offline`: exercise the probe without USB access.
- `meson setup /tmp/goodix-build-c libfprint/goodix5120`, then `meson test -C /tmp/goodix-build-c -v`: test C helpers; requires GLib/OpenSSL development headers. This excludes the actual USB driver.

## Coding Style & Naming Conventions

Use idiomatic Go, tab indentation, `gofmt`, and `go vet`; format changed files without unrelated rewrites. Match existing libfprint/GLib C style: two-space indentation, snake_case functions, and `g5120_` helper names. Document protocol assumptions and distinguish observations from interpretations.

## Testing Guidelines

Use Go's `testing` package (`TestXxx`) and GLib tests (`/goodix5120/...`). Add synthetic regression fixtures for behavior changes and preserve safety tests. Report fixture-dependent skips; no numeric coverage threshold is established.

## Commit & Pull Request Guidelines

Follow history's `feat(scope):`, `fix(scope):`, `test(scope):`, and `docs:` conventions. PRs should explain the problem, behavior change, validation, and hardware assumptions; link relevant issues or plan tasks. Sanitize logs and keep private captures out of diffs.
