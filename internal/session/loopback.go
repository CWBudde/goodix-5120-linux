package session

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/tlspsk"
	"goodix5120/internal/transport"
)

// LoopbackEC is a stand-in for the embedded controller, for rehearsing the
// bridge with no hardware attached.
//
// It is an `openssl s_client` subprocess dressed in Goodix framing. Like the EC
// it is the TLS **client**, it offers only PSK-AES128-CBC-SHA256 over TLS 1.2
// (the suite the vendor log shows in the EC's ClientHello), and it wraps every
// record it emits in a `0xb0` pack. Commands are answered with an ACK built the
// way the device builds one.
//
// What this proves and what it does not:
//
//   - It proves the bridge's framing and sequencing work against a real TLS
//     implementation: real ClientHello, real key derivation, real records. No
//     response bytes are invented, because openssl produces them.
//   - It proves nothing about the EC. The EC's timing, its pack sizes, whether
//     it wants a server flight as one pack or several, and above all whether it
//     accepts the recovered PSK are questions only the device answers
//     (PLAN.md Phase 5b).
//
// It implements transport.Peer rather than session.Device on purpose: wrapped in
// transport.NewPeer it sits behind the same safety gate as the USB path, so a
// rehearsal refuses exactly what a live run refuses.
type LoopbackEC struct {
	bin    string
	psk    string // hex, for the s_client command line
	ln     net.Listener
	logger *log.Logger
	ctx    context.Context
	cancel context.CancelFunc
	accept time.Duration

	// The TLS client is not started until the stand-in is asked for a session,
	// so that it is silent before 0xd0 the way the EC is.
	cmd   *exec.Cmd
	conn  net.Conn
	stdin io.WriteCloser

	mu    sync.Mutex
	queue [][]byte       // synthesised command responses not yet read
	sent  []proto.Opcode // every command it was given, in order

	closeOnce sync.Once
}

// LoopbackConfig configures a LoopbackEC.
type LoopbackConfig struct {
	// PSK is the key the stand-in uses. Give it the same key as the host to
	// rehearse a success, and a different one to rehearse the PSK-rejection
	// path Phase 5b might hit.
	PSK []byte
	// OpenSSL is the binary name or path. Empty means tlspsk.DefaultOpenSSL.
	OpenSSL string
	// Logger receives progress lines. Nil means log.Default().
	Logger *log.Logger
	// Timeout bounds how long StartLoopbackEC waits for s_client to connect.
	// Zero means tlspsk.DefaultTimeout.
	Timeout time.Duration
}

// DeviceCipher is the OpenSSL name of TLS_PSK_WITH_AES_128_CBC_SHA256 (code
// point 0x00ae), the only suite the EC offers.
const DeviceCipher = "PSK-AES128-CBC-SHA256"

// opRequestTLSConnection is `0xd0`. The EC answers it not with an ACK but by
// opening a TLS handshake, so it is what makes this stand-in start its client.
const opRequestTLSConnection proto.Opcode = 0xd0

// StartLoopbackEC prepares the stand-in. The TLS client itself is not started
// until `0xd0` arrives, so that, like the EC, the stand-in says nothing at all
// before it is asked for a session.
//
// That detail matters more than it looks. When the stand-in handshook at connect
// time instead, its ClientHello was already sitting in the socket when the bisect
// attach step drained the device, and the bridge then waited for a hello that had
// already been thrown away.
func StartLoopbackEC(ctx context.Context, cfg LoopbackConfig) (*LoopbackEC, error) {
	if len(cfg.PSK) == 0 {
		return nil, errors.New("session: LoopbackConfig.PSK is empty")
	}
	if cfg.OpenSSL == "" {
		cfg.OpenSSL = tlspsk.DefaultOpenSSL
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = tlspsk.DefaultTimeout
	}

	bin, err := exec.LookPath(cfg.OpenSSL)
	if err != nil {
		return nil, fmt.Errorf("%w: looked for %q on PATH: %w", tlspsk.ErrOpenSSLMissing, cfg.OpenSSL, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("session: listening for the loopback EC: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	cfg.Logger.Printf("  TLS: loopback EC stand-in ready — it will start an openssl s_client (%s, TLS 1.2) "+
		"when it is asked for a session. NOT the device.", DeviceCipher)
	return &LoopbackEC{
		bin:    bin,
		psk:    hex.EncodeToString(cfg.PSK),
		ln:     ln,
		logger: cfg.Logger,
		ctx:    runCtx,
		cancel: cancel,
		accept: cfg.Timeout,
	}, nil
}

// ensureClient starts the TLS client on first need and waits for it to connect.
func (e *LoopbackEC) ensureClient() error {
	if e.conn != nil {
		return nil
	}
	if e.ln == nil {
		return errors.New("session: the loopback EC is closed")
	}

	// -quiet keeps s_client's own chatter off the wire and makes it relay stdin
	// as application data, which is how SendPlaintext simulates an image.
	cmd := exec.CommandContext(e.ctx, e.bin, "s_client",
		"-psk", e.psk,
		"-connect", e.ln.Addr().String(),
		"-cipher", DeviceCipher,
		"-tls1_2",
		"-quiet",
	)
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("session: loopback EC stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("session: starting the loopback EC: %w", err)
	}
	e.cmd, e.stdin = cmd, stdin

	if err := e.ln.(*net.TCPListener).SetDeadline(time.Now().Add(e.accept)); err != nil {
		return fmt.Errorf("session: setting an accept deadline: %w", err)
	}
	conn, err := e.ln.Accept()
	if err != nil {
		return fmt.Errorf("session: the loopback EC never connected: %w", err)
	}
	e.conn = conn
	e.logger.Printf("  TLS: the loopback EC stand-in opened a session (pid %d)", cmd.Process.Pid)
	return nil
}

// WritePack receives one encoded pack, as the bulk OUT endpoint would.
//
// A TLS-data pack has its records written to the TLS client. A command pack is
// decoded and answered with an ACK, the way the device answers: the EC sends the
// ACK as a separate transfer, and then any data reply. No data replies are
// invented here — only the ACK, whose shape is on record for every command in
// the vendor log.
func (e *LoopbackEC) WritePack(_ context.Context, pack []byte) error {
	flags, payload, err := proto.DecodePack(pack)
	if err != nil {
		return fmt.Errorf("session: the loopback EC was handed something that is not a pack: %w", err)
	}

	if flags == proto.FlagTLSData || flags == proto.FlagTLSAlt {
		if err := e.ensureClient(); err != nil {
			return err
		}
		if _, err := e.conn.Write(payload); err != nil {
			return fmt.Errorf("session: writing %d record byte(s) to the loopback EC: %w", len(payload), err)
		}
		return nil
	}

	cmd, _, err := proto.DecodeMessage(payload)
	if err != nil {
		return fmt.Errorf("session: the loopback EC could not decode a command pack: %w", err)
	}

	e.mu.Lock()
	e.sent = append(e.sent, cmd)
	// 0xae and 0xd0 are the two commands the device answers without an ACK
	// (docs/protocol.md, "Init sequence"). Reproducing that is worth more than
	// an ACK for everything, because the probe's collect loop has a branch for it.
	if cmd != 0xae && cmd != opRequestTLSConnection {
		e.queue = append(e.queue, proto.Encode(proto.AckCmd, []byte{byte(cmd), 0x01}))
	}
	e.mu.Unlock()

	// 0xd0 is answered by opening a session rather than by an ACK, which is the
	// whole reason the client is started lazily.
	if cmd == opRequestTLSConnection {
		return e.ensureClient()
	}
	return nil
}

// ReadTransfer returns the next synthesised command response, or the next TLS
// record the client produced, wrapped in a TLS-data pack.
func (e *LoopbackEC) ReadTransfer(timeout time.Duration) ([]byte, error) {
	e.mu.Lock()
	if len(e.queue) > 0 {
		out := e.queue[0]
		e.queue = e.queue[1:]
		e.mu.Unlock()
		return out, nil
	}
	e.mu.Unlock()

	if e.conn == nil {
		// Before 0xd0 the stand-in has nothing to say, exactly as the EC has
		// nothing to say until it is asked for a session.
		return nil, fmt.Errorf("the loopback EC has not been asked for a session yet: %w", transport.ErrTimeout)
	}
	rec, err := readRecord(e.conn, timeout, DefaultHostBody)
	switch {
	case errors.Is(err, errHostIdle):
		return nil, fmt.Errorf("the loopback EC sent nothing: %w", transport.ErrTimeout)
	case err != nil:
		return nil, err
	}
	return proto.EncodePack(proto.FlagTLSData, rec), nil
}

// SendPlaintext makes the stand-in send b as TLS application data, which is how
// a rehearsal simulates the device sending an image. The bytes go through
// s_client's stdin, so they are really encrypted and really have to be decrypted
// by the host end.
func (e *LoopbackEC) SendPlaintext(b []byte) error {
	if e.stdin == nil {
		return errors.New("session: the loopback EC has no session open, so it cannot send application data")
	}
	if _, err := e.stdin.Write(b); err != nil {
		return fmt.Errorf("session: handing %d byte(s) to the loopback EC: %w", len(b), err)
	}
	return nil
}

// Commands returns every opcode the stand-in was sent, in order. A rehearsal can
// assert on the sequence without the probe having to report it.
func (e *LoopbackEC) Commands() []proto.Opcode {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]proto.Opcode(nil), e.sent...)
}

// Close tears down the subprocess and the loopback connection.
func (e *LoopbackEC) Close() error {
	var errs []error
	e.closeOnce.Do(func() {
		if e.stdin != nil {
			_ = e.stdin.Close()
		}
		if e.conn != nil {
			if err := e.conn.Close(); err != nil {
				errs = append(errs, err)
			}
			e.conn = nil
		}
		if e.ln != nil {
			_ = e.ln.Close()
			e.ln = nil
		}
		if e.cancel != nil {
			e.cancel()
		}
		if e.cmd != nil && e.cmd.Process != nil {
			_ = e.cmd.Process.Kill()
			err := e.cmd.Wait()
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				errs = append(errs, err)
			}
		}
	})
	return errors.Join(errs...)
}

// readRecord reads one whole TLS record from conn, or reports errHostIdle if
// none was started within timeout. It is the same read the bridge performs on
// its own side of the session; see Bridge.readHostRecord for why the first byte
// is read separately.
func readRecord(conn net.Conn, idle, body time.Duration) ([]byte, error) {
	if idle <= 0 {
		idle = DefaultHostIdle
	}
	if body <= 0 {
		body = DefaultHostBody
	}
	// One byte first, with the short idle deadline: that is the question "does
	// this side have anything to say?". The rest of the record is already in
	// flight behind it, so a timeout from there on is a fault, not idleness.
	hdr := make([]byte, proto.TLSRecordHeaderLen)
	if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
		return nil, fmt.Errorf("session: setting a read deadline: %w", err)
	}
	switch _, err := io.ReadFull(conn, hdr[:1]); {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, errHostIdle
	case errors.Is(err, io.EOF):
		return nil, errors.New("session: the TLS peer closed the connection")
	case err != nil:
		return nil, fmt.Errorf("session: reading a TLS record: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(body)); err != nil {
		return nil, fmt.Errorf("session: setting a read deadline: %w", err)
	}
	if _, err := io.ReadFull(conn, hdr[1:]); err != nil {
		return nil, fmt.Errorf("session: reading the rest of a TLS record header: %w", err)
	}
	_, _, _, bodyLen, err := proto.ParseTLSRecordHeader(hdr)
	if err != nil {
		return nil, fmt.Errorf("session: not a TLS record: %w", err)
	}
	rec := make([]byte, proto.TLSRecordHeaderLen+bodyLen)
	copy(rec, hdr)
	if _, err := io.ReadFull(conn, rec[proto.TLSRecordHeaderLen:]); err != nil {
		return nil, fmt.Errorf("session: reading a %d-byte record body: %w", bodyLen, err)
	}
	return rec, nil
}
