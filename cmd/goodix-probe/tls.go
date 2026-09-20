package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"goodix5120/internal/image"
	"goodix5120/internal/proto"
	"goodix5120/internal/session"
	"goodix5120/internal/tlspsk"
	"goodix5120/internal/transport"
)

// --tls is PLAN.md Phase 5b: after the bisect steps have taken the sensor to the
// point the vendor driver requests a TLS session, ask for one and bridge the
// handshake to a local openssl endpoint using the PSK recovered from Windows.
//
// It runs as the tail of a bisect run rather than as a mode of its own, so it
// inherits the whole keyboard-safe procedure: one command per step, a key press
// checked after each, an external keyboard attached, a flushed log. The bridge
// itself is checked the same way — the keyboard is tested again after it.
//
// The one question this answers is whether the EC accepts our PSK. Everything
// else it prints (record counts, the plaintext length) is a bonus.

// sensor geometry, for decoding a captured frame. CONFIRMED from the driver log
// (chip ID 0x2504, "ChicagoHS", sensor type 12) and corroborated by the record
// length; see docs/protocol.md.
const (
	sensorWidth  = 80
	sensorHeight = 64
)

// tlsConfig is what the --tls flags add up to.
type tlsConfig struct {
	enabled bool
	pskPath string
	capture string

	// sendD4 and getImage record whether the operator unlocked the opcodes the
	// bridge would like to send after the handshake.
	sendD4   bool
	getImage bool
}

// opcodes returns the commands the bridge itself may send, so mainBisect can put
// them in the transport's allowlist. They are not --steps: the bridge sends them
// at the points in the exchange where they belong.
func (c tlsConfig) opcodes() []proto.Opcode {
	if !c.enabled {
		return nil
	}
	ops := []proto.Opcode{opRequestTLS}
	if c.sendD4 {
		ops = append(ops, opTLSEstablished)
	}
	if c.getImage {
		ops = append(ops, opGetImage)
	}
	return ops
}

// validate checks the flag combination before anything is opened, so a mistake
// costs a message rather than a live run.
func (c tlsConfig) validate(steps []proto.Opcode, allowed map[proto.Opcode]bool) error {
	if !c.enabled {
		if c.pskPath != "" || c.capture != "" {
			return errors.New("--psk and --capture only mean something with --tls")
		}
		return nil
	}
	if c.pskPath == "" {
		return errors.New("--tls needs --psk FILE: the 32-byte device key, as written by " +
			"`goodix-dpapi -out` (see docs/dpapi-runbook.md). Keep it in gitignored captures/")
	}
	if !allowed[opRequestTLS] {
		return fmt.Errorf("--tls sends request_tls_connection (0x%02x), which needs --allow-d0", byte(opRequestTLS))
	}
	for _, op := range steps {
		if op == opRequestTLS {
			return errors.New("--tls sends 0xd0 itself, at the point where it can catch the EC's " +
				"ClientHello; remove d0 from --steps or the handshake records would be drained before the bridge sees them")
		}
	}
	if c.capture != "" && !c.getImage {
		return fmt.Errorf("--capture asks the EC for a frame with mcu_get_image (0x%02x), which needs --allow-20", byte(opGetImage))
	}
	return nil
}

// startRehearsal brings up the loopback stand-in for `--tls --replay` and wraps
// it in a gated transport.
//
// The scripted replay cannot rehearse a TLS session: a handshake is not a fixed
// list of exchanges. This is the substitute — an openssl s_client dressed in
// Goodix framing — and because it goes through transport.NewPeer it refuses
// exactly the frames a live run refuses.
//
// It opens no device and it is not the EC. What it checks is our side: the
// framing, the sequencing, the PSK file, the decode and the PGM. Pass
// wrongPSK to rehearse the rejection path instead, which is worth seeing once
// before the live run so its output is familiar.
func startRehearsal(ctx context.Context, logger *log.Logger, cfg tlsConfig,
	opts transport.Options, wrongPSK bool) (transport.Transport, *session.LoopbackEC, error) {

	psk, err := tlspsk.LoadPSK(cfg.pskPath)
	if err != nil {
		return nil, nil, err
	}
	if wrongPSK {
		// Flip every byte: a key that is certainly not the one the host end
		// holds, derived without inventing a second key to keep around.
		wrong := make([]byte, len(psk))
		for i, b := range psk {
			wrong[i] = ^b
		}
		psk = wrong
		logger.Printf("  rehearsal: the stand-in holds a DIFFERENT key, to rehearse the rejection path")
	}

	ec, err := session.StartLoopbackEC(ctx, session.LoopbackConfig{PSK: psk, Logger: logger})
	if err != nil {
		return nil, nil, fmt.Errorf("starting the rehearsal stand-in: %w", err)
	}
	logger.Printf("  rehearsal: commands are answered with a synthesised ACK and nothing else — " +
		"the vendor's data replies are not invented here")
	return transport.NewPeer(ec, opts), ec, nil
}

// runTLS is the after-hook mainBisect installs. It owns the device from here on:
// the bisect step loop has finished, and everything below is half duplex, so
// nothing writes to the device while the bridge is reading from it.
func runTLS(ctx context.Context, logger *log.Logger, tr transport.Transport, cfg tlsConfig,
	rehearsal *session.LoopbackEC) error {
	psk, err := tlspsk.LoadPSK(cfg.pskPath)
	if err != nil {
		return err
	}
	// Say what was loaded without saying what it is. The PSK is a device secret
	// and this log file is written to disk.
	logger.Printf("\n--- TLS-PSK bridge (PLAN.md Phase 5b)")
	logger.Printf("  loaded a %d-byte PSK from %s (contents not logged)", len(psk), cfg.pskPath)

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Port -1 asks for an ephemeral loopback port: nothing else needs to find
	// this endpoint, and a fixed 4433 would collide with a previous run that has
	// not finished dying.
	host, err := tlspsk.Start(sessCtx, tlspsk.Config{PSK: psk, Port: -1})
	if err != nil {
		return fmt.Errorf("bringing up the local TLS endpoint: %w", err)
	}
	defer func() { _ = host.Close() }()

	bridge := session.New(tr, host, session.Options{Logger: logger})

	// 0xd0 gets no ACK; the EC answers by opening a handshake, so the bridge
	// must start reading immediately. This is why 0xd0 is not a --steps entry.
	st, ok := stepFor(opRequestTLS)
	if !ok {
		return fmt.Errorf("no catalogue entry for request_tls_connection (0x%02x)", byte(opRequestTLS))
	}
	logger.Printf("  sending %s (0x%02x) — %s", opRequestTLS.Name(), byte(opRequestTLS), st.purpose)
	if err := tr.Send(opRequestTLS, st.payload); err != nil {
		return fmt.Errorf("send request_tls_connection: %w", err)
	}

	if err := bridge.Handshake(ctx); err != nil {
		explainHandshakeFailure(logger, err)
		return err
	}

	// The vendor driver sends 0xd4 immediately after the handshake. Whether the
	// EC needs it before it will produce an image is unknown, which is why it is
	// its own flag rather than an automatic follow-up.
	if cfg.sendD4 {
		if err := sendAndCollect(logger, tr, opTLSEstablished); err != nil {
			return err
		}
	} else {
		logger.Printf("  not sending tls_successfully_established (0x%02x): --allow-d4 was not given",
			byte(opTLSEstablished))
	}

	if cfg.capture == "" {
		logger.Printf("  no --capture given, so no image is requested")
		return nil
	}
	return captureFrame(ctx, logger, tr, bridge, cfg.capture, rehearsal)
}

// captureFrame is PLAN.md Phase 5c: ask for one frame, decrypt it, and write it
// out as a PGM.
func captureFrame(ctx context.Context, logger *log.Logger, tr transport.Transport,
	bridge *session.Bridge, path string, rehearsal *session.LoopbackEC) error {

	st, ok := stepFor(opGetImage)
	if !ok {
		return fmt.Errorf("no catalogue entry for mcu_get_image (0x%02x)", byte(opGetImage))
	}
	logger.Printf("\n--- capture one frame (PLAN.md Phase 5c)")
	logger.Printf("  sending %s (0x%02x) — %s", opGetImage.Name(), byte(opGetImage), st.purpose)
	if err := tr.Send(opGetImage, st.payload); err != nil {
		return fmt.Errorf("send mcu_get_image: %w", err)
	}

	// In a rehearsal nothing would answer, so the stand-in is told to send a
	// synthetic frame. It is a gradient, not an image of anything: what the
	// rehearsal checks is the length arithmetic, the decode and the PGM, not the
	// picture.
	if rehearsal != nil {
		frame, err := syntheticFrame()
		if err != nil {
			return err
		}
		logger.Printf("  rehearsal: the stand-in is sending a %d-byte SYNTHETIC frame — the PGM below is a gradient, not a fingerprint", len(frame))
		if err := rehearsal.SendPlaintext(frame); err != nil {
			return err
		}
	}

	// The image record is large; give it room, and cap what is read at twice the
	// expected length so a misframed stream cannot be read forever.
	want, err := image.PackedLen(sensorWidth, sensorHeight)
	if err != nil {
		return err
	}
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	plain, err := bridge.ReadApplicationData(readCtx, session.DefaultPlaintextIdle, 2*want)
	if err != nil {
		return fmt.Errorf("reading the image plaintext: %w", err)
	}

	// The length is the measurement. 7680 means bare samples, 7693 means
	// upstream's header and trailer; the record on the wire is consistent with
	// both (docs/protocol.md, "How big is an image, really").
	logger.Printf("  decrypted %d plaintext byte(s) — %d would be bare samples, %d wrapped",
		len(plain), want, want+image.FrameHeaderLen+image.FrameTrailerLen)

	samples, layout, err := image.TrimFrame(plain, sensorWidth, sensorHeight)
	if err != nil {
		return fmt.Errorf("the plaintext does not match a known frame layout: %w", err)
	}
	logger.Printf("  layout: %s", layout)

	img, err := image.Decode12BitPacked(samples, sensorWidth, sensorHeight)
	if err != nil {
		return fmt.Errorf("decoding the frame: %w", err)
	}

	// 0o600: this is biometric data. It must also stay out of the repository —
	// .gitignore covers captures/ and *.pgm.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := image.WritePGM(f, img); err != nil {
		return err
	}
	logger.Printf("  wrote %dx%d PGM to %s — biometric data: keep it out of git and out of any issue report",
		img.Width, img.Height, path)
	return nil
}

// syntheticFrame builds a bare frame of packed 12-bit samples that ramps across
// the sensor, for rehearsing the capture path with no device.
func syntheticFrame() ([]byte, error) {
	n, err := image.PackedLen(sensorWidth, sensorHeight)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, n)
	for i := range frame {
		frame[i] = byte(i * 256 / n)
	}
	return frame, nil
}

// sendAndCollect sends a catalogued command and reads its replies, the way the
// bisect step loop does.
func sendAndCollect(logger *log.Logger, tr transport.Transport, op proto.Opcode) error {
	st, ok := stepFor(op)
	if !ok {
		return fmt.Errorf("no catalogue entry for 0x%02x", byte(op))
	}
	logger.Printf("  sending %s (0x%02x) — %s", op.Name(), byte(op), st.purpose)
	if err := tr.Send(op, st.payload); err != nil {
		return fmt.Errorf("send %s: %w", op.Name(), err)
	}
	return collect(logger, tr, op, transport.DefaultTimeout)
}

// explainHandshakeFailure turns the bridge's error into the next thing to do.
// PLAN.md Phase 5b lists the fallbacks; this is that list at the point of
// failure.
func explainHandshakeFailure(logger *log.Logger, err error) {
	switch {
	case errors.Is(err, session.ErrPSKMismatch):
		logger.Printf("\n  THE EC DID NOT ACCEPT THIS PSK.")
		logger.Printf("  This is the PLAN.md Phase 5b wall. In order of preference:")
		logger.Printf("    1. Re-audit the unseal — secondary entropy and master key (docs/dpapi-runbook.md).")
		logger.Printf("       This run is the first real test of the recovered key.")
		logger.Printf("    2. Read the PSK or the entropy from the running Windows driver; local analysis only.")
		logger.Printf("    3. Provision our own PSK with 0xe0 — DESTRUCTIVE, breaks Windows Hello, last resort.")
		logger.Printf("  Record the alert above in docs/protocol.md before trying anything.")
	case errors.Is(err, session.ErrAlert):
		logger.Printf("\n  The handshake was rejected, but not for a reason that means a key mismatch.")
		logger.Printf("  Record the alert in docs/protocol.md: it is new information either way.")
	case errors.Is(err, session.ErrHandshakeTimeout):
		logger.Printf("\n  Neither side finished the handshake. Either the EC never started one —")
		logger.Printf("  check whether the init actually reached the state the vendor reaches before 0xd0 —")
		logger.Printf("  or its records are not arriving as b0 packs. The record counts above say which.")
	}
}
