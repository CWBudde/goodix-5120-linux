# Task runner for the Goodix 27c6:5120 bring-up. `just` with no arguments lists everything.
#
# Everything in here is offline and safe to run: it builds, it tests, or it rehearses against the
# replay transport. There is deliberately NO recipe that touches the device — see "live runs" at the
# bottom for why.
#
# -buildvcs=false is used throughout the repo's docs, so it is used here too.

psk     := "captures/goodix-psk.bin"
pcap    := "dump.pcapng"
evtxlog := "captures/Goodix-FingerprintProvider%4Debug.evtx"
pgm     := "/tmp/goodix-rehearsal.pgm"

# List the available recipes.
default:
    @just --list --unsorted

# ---------------------------------------------------------------------------- build

# Build every command into the repository root.
build: probe pcap-tool evtx-tool dpapi

# Build the probe (the only binary that can open hardware).
probe:
    go build -buildvcs=false ./cmd/goodix-probe

# Build the USBPcap reader.
pcap-tool:
    go build -buildvcs=false ./cmd/goodix-pcap

# Build the Windows event-log reader.
evtx-tool:
    go build -buildvcs=false ./cmd/goodix-evtx

# Build the DPAPI unsealer.
dpapi:
    go build -buildvcs=false ./cmd/goodix-dpapi

# Remove the built binaries.
clean:
    rm -f goodix-probe goodix-pcap goodix-evtx goodix-dpapi

# ---------------------------------------------------------------------------- checks

# Everything a change has to pass: format listing, vet, tests (both tags), build.
check: fmt-check vet test test-destructive build

# Run the whole test suite.
test:
    go test ./...

# go vet over everything.
vet:
    go vet ./...

# Run one test, e.g. `just test-one ./internal/transport TestReplayHappyPath`.
test-one pkg test:
    go test {{pkg}} -run {{test}}

# cmd/goodix-probe's safety tests intentionally fail under the goodix_destructive tag, so only the
# two packages meant to build with it are listed here.
# The tag-aware tests: the destructive opcodes that are compiled out of a default build.
test-destructive:
    go test -tags goodix_destructive ./internal/proto ./internal/transport

# gofmt's opinion. Listing only — internal/dpapi and internal/winreg are knowingly unformatted.
fmt-check:
    @gofmt -l .

# Rewrite files with gofmt. Will also reformat the two files above; check the diff before keeping it.
fmt:
    gofmt -w .

# Check the payload rules against real vendor traffic. Needs the (gitignored) capture.
test-capture:
    go test ./internal/capture -capture "$PWD/{{pcap}}"

# Re-derive the 17545 / 18 / 9 figures from the driver log. Needs the (gitignored) log.
test-evtx:
    go test ./internal/evtx -log "$PWD/{{evtxlog}}"

# ---------------------------------------------------------------------------- offline probe runs

# Print the frames the probe would send. Opens no USB device.
dry-run: probe
    ./goodix-probe --dry-run

# The full decode path against the scripted fake.
replay: probe
    ./goodix-probe --replay

# The bisect flow offline: no root, no USB.
bisect-offline: probe
    ./goodix-probe --bisect --replay --assume-keys

# ---------------------------------------------------------------------------- TLS-PSK rehearsals
#
# The "EC" in these is an `openssl s_client` wearing Goodix framing, so the TLS bytes are real and
# the device is not. They need openssl on PATH and the recovered PSK at {{psk}}
# (see docs/dpapi-runbook.md). Nothing here opens hardware.

# Rehearse the handshake (PLAN.md 5b). Expect `handshake complete`.
rehearse-handshake: probe
    ./goodix-probe --bisect --replay --assume-keys --tls --psk {{psk}} \
      --allow-d0 --allow-d4 --steps a8

# Rehearse a PSK the EC rejects, so its output is familiar before it matters. Exits non-zero.
rehearse-rejection: probe
    ./goodix-probe --bisect --replay --assume-keys --tls --psk {{psk}} \
      --allow-d0 --steps a8 --rehearse-rejection

# Rehearse the frame capture (PLAN.md 5c). The stand-in sends a gradient, so the PGM is a ramp.
rehearse-capture: probe
    ./goodix-probe --bisect --replay --assume-keys --tls --psk {{psk}} \
      --allow-d0 --allow-d4 --allow-20 --steps a8 --capture {{pgm}}

# All three rehearsals. rehearse-rejection is expected to exit 1, hence the `-`.
rehearse: rehearse-handshake rehearse-capture
    -@just rehearse-rejection

# ---------------------------------------------------------------------------- live runs

# Why there is no `just live-…`, and where the real procedure is.
live-help:
    @echo 'There is no recipe that runs against the device, on purpose.'
    @echo
    @echo 'A live run wedged the ITE EC and killed the internal keyboard (FINDINGS.md). The'
    @echo 'safety of this repository is friction: one command per run, every state-changing'
    @echo 'frame behind its own --allow-XX flag, an external keyboard attached, and a human'
    @echo 'deciding each step. A recipe that hides `sudo --allow-90` behind a short name'
    @echo 'removes exactly the friction that is the safeguard, so the command lines stay'
    @echo 'where the procedure around them is written down:'
    @echo
    @echo '    docs/bisect-runbook.md'
    @echo
    @echo 'Rehearse offline first: just rehearse'
