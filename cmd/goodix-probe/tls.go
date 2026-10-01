package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"goodix5120/internal/image"
	"goodix5120/internal/privatefile"
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
// inherits the whole bisect procedure: the 0xa8 health check, one command per
// step, a flushed log, and the host's counters logged after the bridge too.
//
// The one question this answers is whether the EC accepts our PSK. Everything
// else it prints (record counts, the plaintext length) is a bonus.

// sensor geometry, for decoding a captured frame: 64 samples per row, 80 rows.
// The sample count (5120) comes from the driver log (chip ID 0x2504,
// "ChicagoHS", sensor type 12) and the record length. The orientation comes
// from the first real frame (Run 20): read 80 wide, neighbouring rows differ
// about five times as much as read 64 wide, and only 64 wide shows continuous
// ridges. Upstream's write_pgm swaps the header's fields for the same reason.
const (
	sensorWidth  = 64
	sensorHeight = 80
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

	// waitFinger takes the frame when the EC reports a finger instead of at
	// once (PLAN.md Phase 5d), touches times in one session; fingerTimeout
	// bounds each wait. armDown and armUp record whether the two arms it sends
	// were unlocked.
	waitFinger    bool
	touches       int
	fingerTimeout time.Duration
	armDown       bool
	armUp         bool

	// steps is what the bisect run sends before the bridge, so a stall can be
	// read against the vendor's init (vendorBeforeTLS).
	steps []proto.Opcode
}

// vendorBeforeTLS is the vendor's init up to, not including, 0xd0: the state
// the EC is in when the vendor's handshakes succeed.
func vendorBeforeTLS() []proto.Opcode {
	var ops []proto.Opcode
	for _, st := range vendorInit {
		if st.cmd == opRequestTLS {
			break
		}
		ops = append(ops, st.cmd)
	}
	return ops
}

// missingFromVendorInit lists the commands of the vendor's pre-0xd0 init that
// steps does not send. Run 11 left out 0xe4 and stalled; the vendor sends it in
// every init, and its handshakes complete. Commands are counted, not just
// looked up: the vendor sends 0xa2 twice, and one 0xa2 in steps covers only one
// of them.
func missingFromVendorInit(steps []proto.Opcode) []proto.Opcode {
	sent := make(map[proto.Opcode]int)
	for _, op := range steps {
		sent[op]++
	}
	var missing []proto.Opcode
	for _, op := range vendorBeforeTLS() {
		if sent[op] > 0 {
			sent[op]--
			continue
		}
		missing = append(missing, op)
	}
	return missing
}

// opList formats opcodes the way --steps takes them.
func opList(ops []proto.Opcode) string {
	parts := make([]string, len(ops))
	for i, op := range ops {
		parts[i] = fmt.Sprintf("%02x", byte(op))
	}
	return strings.Join(parts, ",")
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
	if c.waitFinger && c.armDown {
		ops = append(ops, opFDTDown)
	}
	if c.waitFinger && c.armUp {
		ops = append(ops, opFDTUp)
	}
	return ops
}

// validate checks the flag combination before anything is opened, so a mistake
// costs a message rather than a live run.
func (c tlsConfig) validate(steps []proto.Opcode, allowed map[proto.Opcode]bool, replay bool) error {
	if !c.enabled {
		if c.pskPath != "" || c.capture != "" || c.waitFinger {
			return errors.New("--psk, --capture and --wait-finger only mean something with --tls")
		}
		return nil
	}
	if !replay && c.pskPath == "" {
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
	if c.waitFinger {
		switch {
		case c.capture == "":
			return errors.New("--wait-finger waits for a finger in order to take a frame; it needs --capture")
		case !c.armDown || !c.armUp:
			return fmt.Errorf("--wait-finger arms fdt_down (0x%02x) and fdt_up (0x%02x), which need --allow-32 and --allow-34",
				byte(opFDTDown), byte(opFDTUp))
		case c.fingerTimeout <= 0:
			return errors.New("--finger-timeout must be positive")
		}
	}
	switch {
	case c.touches > 1 && !c.waitFinger:
		return errors.New("--touches repeats the --wait-finger loop; it needs --wait-finger")
	case c.touches < 0 || c.touches > maxTouches:
		return fmt.Errorf("--touches must be between 1 and %d", maxTouches)
	}
	return nil
}

// preparedTLS owns an endpoint which was validated before any hardware
// is opened. Rehearsals use only a public synthetic key, never the device key.
type preparedTLS struct {
	host         *tlspsk.Session
	rehearsalPSK []byte
}

func prepareTLS(ctx context.Context, cfg tlsConfig, replay bool,
	start func(context.Context, tlspsk.Config) (*tlspsk.Session, error)) (*preparedTLS, error) {
	if !cfg.enabled {
		return nil, nil
	}
	var psk []byte
	var err error
	if replay {
		psk = tlspsk.ReferencePSK()
	} else {
		psk, err = tlspsk.LoadPSK(cfg.pskPath)
		if err != nil {
			return nil, err
		}
	}
	defer clear(psk)
	host, err := start(ctx, tlspsk.Config{PSK: psk})
	if err != nil {
		return nil, err
	}
	prepared := &preparedTLS{host: host}
	if replay {
		prepared.rehearsalPSK = append([]byte(nil), psk...)
	}
	return prepared, nil
}

func (p *preparedTLS) close() {
	_ = p.host.Close()
	clear(p.rehearsalPSK)
}

// startRehearsal brings up the loopback stand-in for `--tls --replay` and wraps
// it in a gated transport.
//
// The scripted replay cannot rehearse a TLS session: a handshake is not a fixed
// list of exchanges. This is the substitute — an in-process OpenSSL client dressed in
// Goodix framing — and because it goes through transport.NewPeer it refuses
// exactly the frames a live run refuses.
//
// It opens no device and it is not the EC. What it checks is our side: the
// framing, the sequencing, the decode and the PGM using a synthetic key. Pass
// wrongPSK to rehearse the rejection path instead, which is worth seeing once
// before the live run so its output is familiar.
func startRehearsal(ctx context.Context, logger *log.Logger, prepared *preparedTLS,
	opts transport.Options, wrongPSK bool) (transport.Transport, *session.LoopbackEC, error) {

	psk := append([]byte(nil), prepared.rehearsalPSK...)
	defer clear(psk)
	if wrongPSK {
		// Flip every byte: a key that is certainly not the one the host end
		// holds, derived without inventing a second key to keep around.
		wrong := make([]byte, len(psk))
		for i, b := range psk {
			wrong[i] = ^b
		}
		clear(psk)
		psk = wrong
		defer clear(wrong)
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
	rehearsal *session.LoopbackEC, host *tlspsk.Session) error {
	logger.Printf("\n--- TLS-PSK bridge (PLAN.md Phase 5b)")
	logger.Printf("  using the preflighted in-process TLS endpoint (key contents withheld)")

	bridge := session.New(tr, host, session.Options{Logger: logger})
	if missing := missingFromVendorInit(cfg.steps); rehearsal == nil && len(missing) > 0 {
		logger.Printf("  WARNING: the steps left out %s, which the vendor sends before 0xd0 in every init", opList(missing))
		logger.Printf("  (vendor: --steps %s). A stall now says nothing about the key or the framing.", opList(vendorBeforeTLS()))
	}

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
		toHost, toDevice := bridge.Counts()
		explainHandshakeFailure(logger, err, cfg, toHost, toDevice)
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
	if cfg.waitFinger {
		return captureOnTouch(ctx, logger, tr, bridge, cfg, rehearsal)
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
	if layout == image.LayoutWrapped {
		// The 13 bytes around the samples are not image data, and what they
		// hold is open (PLAN.md Phase 6). Frames from one session side by side
		// are the cheapest way to see which bytes count, which stay put and
		// which follow the finger.
		logger.Printf("  frame header %x, trailer %x", plain[:image.FrameHeaderLen], plain[len(plain)-image.FrameTrailerLen:])
	}

	img, err := image.Decode12BitPacked(samples, sensorWidth, sensorHeight)
	if err != nil {
		return fmt.Errorf("decoding the frame: %w", err)
	}

	if err := writeCapture(path, img); err != nil {
		return err
	}
	logger.Printf("  wrote %dx%d PGM to %s — biometric data: keep it out of git and out of any issue report",
		img.Width, img.Height, path)
	return nil
}

// writeCapture publishes an encoded image privately and atomically.
func writeCapture(path string, img image.Gray8) error {
	var pgm bytes.Buffer
	if err := image.WritePGM(&pgm, img); err != nil {
		return err
	}
	owner, err := sudoOwnership()
	if err != nil {
		return err
	}
	if err := privatefile.Write(path, pgm.Bytes(), owner); err != nil {
		return fmt.Errorf("writing private capture: %w", err)
	}
	return nil
}

// sudoOwnership is applied to the temporary capture before publication.
// A malformed sudo identity cannot silently publish an unreadable root-owned file.
func sudoOwnership() (*privatefile.Ownership, error) {
	return captureOwnership(os.Geteuid(), os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"))
}

func captureOwnership(euid int, u, g string) (*privatefile.Ownership, error) {
	if euid != 0 {
		return nil, nil
	}
	if u == "" && g == "" {
		return nil, nil
	}
	uid, e1 := strconv.Atoi(u)
	gid, e2 := strconv.Atoi(g)
	if e1 != nil || e2 != nil || uid < 0 || gid < 0 || uint64(uid) >= 1<<32-1 || uint64(gid) >= 1<<32-1 {
		return nil, errors.New("invalid SUDO_UID/SUDO_GID for capture ownership")
	}
	return &privatefile.Ownership{UID: uid, GID: gid}, nil
}

// giveToSudoUser hands a file the probe created under sudo to the user who ran
// sudo, keeping its mode. A live run is root, so without this every capture
// and log is root-owned 0600 and the user who took it cannot open it.
func giveToSudoUser(logger *log.Logger, f *os.File) {
	if os.Geteuid() != 0 {
		return
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		return
	}
	if err := f.Chown(uid, gid); err != nil {
		logger.Printf("  could not hand %s to uid %d: %v", f.Name(), uid, err)
	}
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
func explainHandshakeFailure(logger *log.Logger, err error, cfg tlsConfig, toHost, toDevice int) {
	switch {
	case errors.Is(err, session.ErrHandshakeTimeout):
		explainStall(logger, cfg, toHost, toDevice)
	case errors.Is(err, session.ErrPSKMismatch):
		logger.Printf("\n  TLS authentication failed: a PSK mismatch or corrupted records are possible.")
		logger.Printf("  Local TLS policy passed preflight. Check authentication evidence before changing the key:")
		logger.Printf("    1. Re-audit the unseal — secondary entropy and master key (docs/dpapi-runbook.md).")
		logger.Printf("       This run is the first real test of the recovered key.")
		logger.Printf("    2. Read the PSK or the entropy from the running Windows driver; local analysis only.")
		logger.Printf("    3. Provision our own PSK with 0xe0 — DESTRUCTIVE, breaks Windows Hello, last resort.")
		logger.Printf("  Record the alert above in docs/protocol.md before trying anything.")
	case errors.Is(err, session.ErrAlert):
		logger.Printf("\n  The handshake was rejected, but not for a reason that means a key mismatch.")
		logger.Printf("  Record the alert in docs/protocol.md: it is new information either way.")
	}
}

// explainStall reads a timed-out handshake off the record counts. Which of these
// happened decides what to change next, and they want opposite changes, so the
// counts are worth printing rather than one generic message.
func explainStall(logger *log.Logger, cfg tlsConfig, toHost, toDevice int) {
	switch {
	case toHost == 0:
		logger.Printf("\n  The EC never started a handshake: nothing arrived as a b0 pack.")
		logger.Printf("  That points at the init, not at the key — check whether the steps really reached")
		logger.Printf("  the state the vendor reaches before 0xd0 (docs/protocol.md, the vendor's 14 frames).")
	case toDevice == 0:
		logger.Printf("\n  The EC opened a handshake and the host answered nothing, which is a fault on")
		logger.Printf("  our side: openssl should reply to a ClientHello in under a millisecond. Check the")
		logger.Printf("  local endpoint error above and the effective OpenSSL policy for 0x00ae.")
	case len(missingFromVendorInit(cfg.steps)) > 0:
		logger.Printf("\n  The EC opened a handshake, went quiet after the server flight, and sent no alert.")
		logger.Printf("  This run left out %s, which the vendor sends before 0xd0 in every init — and the", opList(missingFromVendorInit(cfg.steps)))
		logger.Printf("  vendor's handshakes complete. Rule that out first: run the vendor's init in full")
		logger.Printf("  (--steps %s) before changing anything about the TLS side.", opList(vendorBeforeTLS()))
	default:
		logger.Printf("\n  The EC opened a handshake, went quiet after the server flight, and sent no alert —")
		logger.Printf("  so it did not fail to parse what it got. The init, the framing and the bridge's read")
		logger.Printf("  timing were the vendor's (Run 17's fix: the device is read throughout the EC's flight).")
		logger.Printf("  Look first at the timestamps above: a zero-length transfer where the EC's next record")
		logger.Printf("  should be means it was not read in time. Otherwise the suspects are the flight's")
		logger.Printf("  contents, in order of cheapness:")
		logger.Printf("    1. The ServerHello carries a 32-byte session id and a renegotiation_info")
		logger.Printf("       extension; the EC's own ClientHello carries no extensions field at all.")
		logger.Printf("    2. There is no ServerKeyExchange, because the host sets no PSK identity hint.")
		logger.Printf("  The vendor's flight has the same shape (docs/protocol.md), so neither is likely.")
		logger.Printf("  Both are openssl's output, and a record cannot be edited on the way past: the")
		logger.Printf("  Finished MACs cover the transcript, so rewriting a byte here breaks the handshake")
		logger.Printf("  it is meant to fix. Changing either means an openssl option or our own TLS-PSK")
		logger.Printf("  server. Record the transcript above in docs/protocol.md first — it is the evidence.")
	}
}
