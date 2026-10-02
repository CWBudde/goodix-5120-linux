# Task runner for the Goodix 27c6:5120 bring-up. `just` with no arguments lists everything.
#
# Everything in here is offline and safe to run: it builds, it tests, or it rehearses against the
# replay transport. There is deliberately NO recipe that touches the device — see "live runs" at the
# bottom for why.
#
# -buildvcs=false is used throughout the repo's docs, so it is used here too.

pcap := "dump.pcapng"
evtxlog := "captures/Goodix-FingerprintProvider%4Debug.evtx"
pgm := "/tmp/goodix-rehearsal.pgm"

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

# Everything a change has to pass: format, lint, vet, Go tests (both tags), C tests, build, tidy.
check: fmt-check lint vet test test-destructive test-c build check-tidy

# Run the whole test suite.
test:
    go test ./...

# go vet over everything.
vet:
    go vet ./...

# Run one test, e.g. `just test-one ./internal/transport TestReplayHappyPath`.
test-one pkg test:
    go test {{ pkg }} -run {{ test }}

# The tag-aware tests: the destructive opcodes that are compiled out of a default build.
# cmd/goodix-probe's safety tests intentionally fail under this tag, so only the two packages meant

# to build with it are listed.
test-destructive:
    go test -tags goodix_destructive ./internal/proto ./internal/transport

# Format everything with treefmt (gofumpt, gci, prettier, shfmt, taplo, yamlfmt, just).
fmt:
    treefmt --allow-missing-formatter

# Fail if anything is not formatted.
fmt-check:
    treefmt --allow-missing-formatter --fail-on-change

# golangci-lint, plus shellcheck on the shell scripts.
lint:
    golangci-lint run --timeout 5m
    shellcheck libfprint/goodix5120/build/build-bundle.sh libfprint/goodix5120/fprintd/goodix5120-fprintd.sh

# golangci-lint with fixes applied.
lint-fix:
    golangci-lint run --timeout 5m --fix

# Fail if go.mod / go.sum are not tidy.
check-tidy:
    @go mod tidy
    @git diff --exit-code go.mod go.sum || { echo "go.mod/go.sum not tidy. Run 'go mod tidy'."; exit 1; }

# The C driver's offline tests: fake libfprint/USB and a synthetic EC, normal and under ASan/UBSan.
test-c:
    meson setup --reconfigure /tmp/g5120 libfprint/goodix5120 >/dev/null 2>&1 || meson setup /tmp/g5120 libfprint/goodix5120 >/dev/null
    meson test -C /tmp/g5120 --print-errorlogs
    meson setup --reconfigure /tmp/g5120-asan libfprint/goodix5120 -Db_sanitize=address,undefined >/dev/null 2>&1 || meson setup /tmp/g5120-asan libfprint/goodix5120 -Db_sanitize=address,undefined >/dev/null
    meson test -C /tmp/g5120-asan --print-errorlogs

# Check the payload rules against real vendor traffic. Needs the (gitignored) capture.
test-capture:
    go test ./internal/capture -capture "$PWD/{{ pcap }}"

# Re-derive the 17545 / 18 / 9 figures from the driver log. Needs the (gitignored) log.
test-evtx:
    go test ./internal/evtx -log "$PWD/{{ evtxlog }}"

# ---------------------------------------------------------------------------- offline probe runs

# Print the frames the probe would send. Opens no USB device.
dry-run: probe
    ./goodix-probe --dry-run

# The bisect flow offline: no root, no USB.
bisect-offline: probe
    ./goodix-probe --bisect --replay

# ---------------------------------------------------------------------------- TLS-PSK rehearsals
#
# The "EC" is an in-process OpenSSL PSK client wearing Goodix framing. Both
# endpoints use a public synthetic key; no recovered device key is read.
# Builds require OpenSSL >= 3 development headers. Nothing here opens hardware.

# Rehearse the handshake (PLAN.md 5b). Expect `handshake complete`.
rehearse-handshake: probe
    ./goodix-probe --bisect --replay --tls \
      --allow-d0 --allow-d4 --steps a8

# Rehearse a PSK the EC rejects, so its output is familiar before it matters. Exits non-zero.
rehearse-rejection: probe
    ./goodix-probe --bisect --replay --tls \
      --allow-d0 --steps a8 --rehearse-rejection

# Rehearse the frame capture (PLAN.md 5c). The stand-in sends a gradient, so the PGM is a ramp.
rehearse-capture: probe
    ./goodix-probe --bisect --replay --tls \
      --allow-d0 --allow-d4 --allow-20 --steps a8 --capture {{ pgm }}

# Rehearse several touches in one TLS session (PLAN.md 5d/6). The stand-in plays a finger.
rehearse-touches: probe
    ./goodix-probe --bisect --replay --tls \
      --allow-d0 --allow-d4 --allow-20 --allow-32 --allow-34 --steps a8 \
      --capture {{ pgm }} --wait-finger --touches 3 --finger-timeout 3s

# All the rehearsals. rehearse-rejection is expected to exit 1, hence the `-`.
rehearse: rehearse-handshake rehearse-capture rehearse-touches
    -@just rehearse-rejection

# ---------------------------------------------------------------------------- driver bundle

libfprint_rev := "6f9479c3d55f847c1b3769f28ceb99227f9858cf"
build_image := "goodix5120-build:26.04"

# Build the driver bundle (pinned libfprint + goodix5120) in docker, offline, into dist/.
bundle version=`git describe --tags --always --dirty`:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d .cache/libfprint/.git ]; then
        git clone --quiet https://gitlab.freedesktop.org/libfprint/libfprint.git .cache/libfprint
    fi
    git -C .cache/libfprint checkout --quiet --detach {{ libfprint_rev }}
    docker buildx version >/dev/null 2>&1 || export DOCKER_BUILDKIT=0   # legacy builder without buildx
    docker build --quiet -t {{ build_image }} libfprint/goodix5120/build >/dev/null
    out=dist/goodix5120-{{ version }}
    mkdir -p "$out"
    docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
        -e VERSION={{ version }} -v "$PWD:/src:ro" -v "$PWD/.cache/libfprint:/libfprint:ro" -v "$PWD/$out:/out" \
        {{ build_image }} sh /src/libfprint/goodix5120/build/build-bundle.sh

# ---------------------------------------------------------------------------- live runs

# Why there is no `just live-…`, and where the real procedure is.
live-help:
    @echo 'There is no recipe that runs against the device, on purpose.'
    @echo
    @echo 'A live run wedged the ITE EC and killed the internal keyboard (Run 1). The'
    @echo 'safety of this repository is friction: one command per run, every state-changing'
    @echo 'frame behind its own --allow-XX flag, the 0xa8 health check, an external keyboard,'
    @echo 'and a human'
    @echo 'deciding each step. A recipe that hides `sudo --allow-90` behind a short name'
    @echo 'removes exactly the friction that is the safeguard. The driver runs through'
    @echo 'fprintd (docs/fprintd.md); every live probe command line is in its run record in'
    @echo 'docs/protocol.md, and "Recovering the EC" there says what to do if it wedges.'
    @echo
    @echo 'Rehearse offline first: just rehearse'
