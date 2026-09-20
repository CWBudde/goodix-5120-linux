// Package tlspsk brings up a TLS-PSK endpoint by driving an `openssl s_server`
// subprocess.
//
// Why a subprocess: the Goodix 51x0 protocol secures its image transfer with
// TLS-PSK, and Go's crypto/tls implements no PSK cipher suites, so a pure-Go
// handshake is not available. The upstream Python reference implementation
// (github.com/goodix-fp-linux-dev/goodix-fp-dump, driver_51x0.py, run_driver)
// works around this by spawning
//
//	openssl s_server -nocert -psk <hex> -port 4433 -quiet
//
// and connecting to it as a plain TCP client.
//
// The direction of that plumbing is easy to get backwards, so to be explicit
// (CONFIRMED by reading tool.connect_device and run_driver upstream):
//
//   - The TCP socket is the CIPHERTEXT side. It carries raw TLS records to and
//     from the device: upstream writes device.request_tls_connection() straight
//     into the socket and forwards whatever comes back to the device.
//   - The subprocess's stdin/stdout is the PLAINTEXT side, i.e. TLS application
//     data. Upstream reads the decrypted fingerprint image out of
//     tls_server.stdout.
//
// This package follows that mapping: Session.Read/Write are plaintext (the
// subprocess pipes) and Session.Device is the ciphertext socket.
//
// Tier 2 scaffolding: nothing in the shipped Tier 1 probe calls this package.
package tlspsk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// PSKLen is the length in bytes of the 51x0 TLS pre-shared key. The reference
// key and the recovered device key are both this length.
const PSKLen = 32

// ReferencePSKHex is the pre-shared key used by the upstream reference
// implementation for the 51x0 family: 32 zero bytes.
//
// CONFIRMED from goodix-fp-dump driver_51x0.py, which defines
//
//	PSK = bytes.fromhex("00" * 32)
//
// and passes PSK.hex() to `openssl s_server -psk`. Note this is distinct from
// PSK_WHITE_BOX (the 96-byte blob written to the device's PSK slot) and from
// PMK_HASH (the SHA-256 the device reports back); only this value is the TLS
// pre-shared key.
//
// It is exported as a documented constant so its provenance stays visible. The
// package never uses it implicitly — callers must put it in Config.PSK.
const ReferencePSKHex = "0000000000000000000000000000000000000000000000000000000000000000"

// ReferencePSK returns a fresh copy of ReferencePSKHex decoded to bytes.
func ReferencePSK() []byte {
	b, err := hex.DecodeString(ReferencePSKHex)
	if err != nil {
		panic("tlspsk: malformed ReferencePSKHex: " + err.Error())
	}
	return b
}

// LoadPSK reads a raw pre-shared key from a file: exactly PSKLen bytes, the
// form `cmd/goodix-dpapi -out` writes. This is how the Phase 5 recovered device
// PSK — kept only in gitignored captures/ — reaches Config.PSK, without the
// secret ever entering the repository or being hardcoded here. A wrong length
// is an error rather than a silent truncation, which also catches a hex dump
// handed in where raw bytes were meant. The returned slice is the caller's own.
func LoadPSK(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlspsk: reading PSK file %q: %w", path, err)
	}
	if len(b) != PSKLen {
		return nil, fmt.Errorf("tlspsk: PSK file %q is %d bytes, want %d "+
			"(a raw key as written by goodix-dpapi -out, not hex)", path, len(b), PSKLen)
	}
	return b, nil
}

// ParsePSKHex decodes a hex-encoded pre-shared key to PSKLen bytes. It accepts
// surrounding whitespace, so it can take the output of `goodix-dpapi -print-psk`
// or a command-line flag directly, and matches the form of ReferencePSKHex.
func ParsePSKHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("tlspsk: malformed PSK hex: %w", err)
	}
	if len(b) != PSKLen {
		return nil, fmt.Errorf("tlspsk: PSK hex decodes to %d bytes, want %d", len(b), PSKLen)
	}
	return b, nil
}

// Defaults applied by Start when the corresponding Config field is zero.
const (
	DefaultPort    = 4433 // CONFIRMED: driver_51x0.py uses -port 4433.
	DefaultOpenSSL = "openssl"
	DefaultTimeout = 10 * time.Second
)

// Config configures a Session.
type Config struct {
	// PSK is the pre-shared key. Required; there is no implicit default, see
	// ReferencePSK for the upstream value.
	PSK []byte
	// Port is the loopback TCP port openssl listens on. Zero means
	// DefaultPort. Use a negative value to request an ephemeral free port,
	// which is what the tests do to avoid collisions.
	Port int
	// OpenSSL is the binary name or path. Empty means DefaultOpenSSL.
	OpenSSL string
	// Timeout bounds how long Start waits for the subprocess to accept a
	// connection. Zero means DefaultTimeout.
	Timeout time.Duration
	// Cipher, when non-empty, is passed to `s_server -cipher <Cipher>` to
	// constrain the TLS 1.2 cipher list the server offers. Empty (the default)
	// leaves openssl's own default list untouched, which is what upstream does
	// and what the ReferencePSK path relies on.
	//
	// The 51x0 device is the client and offers only 0x00AE
	// (TLS_PSK_WITH_AES_128_CBC_SHA256, openssl name PSK-AES128-CBC-SHA256), a
	// TLS 1.2 CBC-SHA256 suite. On the openssl this was validated against
	// (3.5.5) it negotiates fine at the default security level with an empty
	// Cipher, so no value is needed here. This knob exists for distributions
	// whose default s_server list drops legacy CBC PSK suites or raises the
	// security level past level 2, where forcing e.g.
	// "PSK-AES128-CBC-SHA256:@SECLEVEL=0" restores the suite.
	Cipher string
}

func (c Config) withDefaults() Config {
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.OpenSSL == "" {
		c.OpenSSL = DefaultOpenSSL
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	return c
}

// ErrOpenSSLMissing is reported when the openssl binary cannot be found.
var ErrOpenSSLMissing = errors.New("tlspsk: openssl binary not found")

// Session owns a running `openssl s_server` subprocess and the loopback
// connection to it.
//
// Write sends plaintext (TLS application data) into the endpoint; the
// resulting ciphertext records appear on Device, which is what must be
// forwarded to the fingerprint sensor. Read returns plaintext decrypted from
// the TLS records previously written to Device.
type Session struct {
	cmd    *exec.Cmd
	conn   net.Conn
	stdin  io.WriteCloser
	stdout io.ReadCloser
	port   int

	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
	waitDone  chan struct{}
}

// Start launches the openssl s_server subprocess and connects to it.
//
// The subprocess is bound to loopback only and is torn down when the session is
// closed or when ctx is cancelled, whichever happens first.
func Start(ctx context.Context, cfg Config) (*Session, error) {
	cfg = cfg.withDefaults()

	if len(cfg.PSK) == 0 {
		return nil, errors.New("tlspsk: Config.PSK is empty; see ReferencePSK for the upstream value")
	}

	bin, err := exec.LookPath(cfg.OpenSSL)
	if err != nil {
		return nil, fmt.Errorf("%w: looked for %q on PATH; install the OpenSSL command line tools "+
			"(Debian/Ubuntu: apt install openssl, Fedora: dnf install openssl, Arch: pacman -S openssl): %w",
			ErrOpenSSLMissing, cfg.OpenSSL, err)
	}

	port := cfg.Port
	if port < 0 {
		if port, err = freeLoopbackPort(); err != nil {
			return nil, err
		}
	}

	// A derived cancellable context so Close can kill the process even when
	// the caller's context never fires, and vice versa.
	runCtx, cancel := context.WithCancel(ctx)

	// -accept 127.0.0.1:<port> binds loopback only. Upstream uses
	// `-port <port>`, which binds all interfaces; restricting to loopback is
	// OUR change, since the device bridge is always local.
	args := []string{
		"s_server",
		"-nocert",
		"-psk", hex.EncodeToString(cfg.PSK),
		"-accept", fmt.Sprintf("127.0.0.1:%d", port),
		"-quiet",
	}
	if cfg.Cipher != "" {
		args = append(args, "-cipher", cfg.Cipher)
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	// Kill rather than interrupt, and do not let CommandContext's Wait block
	// on the pipes.
	cmd.Cancel = func() error { return cmd.Process.Kill() }

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("tlspsk: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("tlspsk: stdout pipe: %w", err)
	}
	// Upstream merges stderr into stdout; we must not, or openssl's diagnostics
	// would be interleaved into the ciphertext stream.
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("tlspsk: starting %s s_server: %w", bin, err)
	}

	s := &Session{
		cmd:      cmd,
		stdin:    stdin,
		stdout:   stdout,
		port:     port,
		cancel:   cancel,
		waitDone: make(chan struct{}),
	}

	conn, err := dialUntil(runCtx, port, cfg.Timeout)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.conn = conn

	// Reap on context cancellation. cmd.Cancel kills the process, but nothing
	// calls Wait, so without this the child would linger as a zombie until
	// Close. Close is idempotent, so a later explicit Close is still fine.
	go func() {
		<-runCtx.Done()
		_ = s.Close()
	}()

	return s, nil
}

// dialUntil retries a loopback connect until the listener is up or the deadline
// passes. openssl needs a moment to bind after fork/exec.
func dialUntil(ctx context.Context, port int, timeout time.Duration) (net.Conn, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("tlspsk: connecting to %s: %w", addr, err)
		}
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		last = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("tlspsk: timed out after %s connecting to openssl s_server on %s: %w",
				timeout, addr, last)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("tlspsk: connecting to %s: %w", addr, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func freeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("tlspsk: reserving a loopback port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Port reports the loopback port the subprocess listens on.
func (s *Session) Port() int { return s.port }

// Write sends plaintext application data into the TLS endpoint; the encrypted
// form is then readable from Device. It writes to the subprocess's stdin.
func (s *Session) Write(p []byte) (int, error) {
	if s.closed() {
		return 0, errors.New("tlspsk: session is closed")
	}
	if s.stdin == nil {
		return 0, errors.New("tlspsk: session not started")
	}
	return s.stdin.Write(p)
}

// Read returns plaintext decrypted from the TLS records previously written to
// Device. It reads the subprocess's stdout, which is where upstream reads the
// decrypted fingerprint image from.
func (s *Session) Read(p []byte) (int, error) {
	if s.closed() {
		return 0, errors.New("tlspsk: session is closed")
	}
	if s.stdout == nil {
		return 0, errors.New("tlspsk: session not started")
	}
	return s.stdout.Read(p)
}

// Device is the ciphertext side: the loopback socket carrying raw TLS records.
// Read TLS records from it to forward to the fingerprint sensor, and write the
// records the sensor produced into it.
func (s *Session) Device() net.Conn { return s.conn }

func (s *Session) closed() bool {
	select {
	case <-s.waitDone:
		return true
	default:
		return false
	}
}

// Close terminates the subprocess and releases the connection. It is safe to
// call more than once; subsequent calls return the first result.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		var errs []error
		if s.conn != nil {
			if err := s.conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.stdin != nil {
			_ = s.stdin.Close()
		}

		// Cancel first: this kills the process via cmd.Cancel. Then drain
		// stdout so Wait cannot block on the pipe copy.
		s.cancel()
		if s.stdout != nil {
			go func() { _, _ = io.Copy(io.Discard, s.stdout) }()
		}

		if s.cmd != nil && s.cmd.Process != nil {
			// Belt and braces: kill directly too, in case cmd.Cancel raced.
			_ = s.cmd.Process.Kill()
			err := s.cmd.Wait()
			// A killed process reports an ExitError; that is the expected
			// outcome, not a failure.
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				errs = append(errs, err)
			}
		}
		close(s.waitDone)
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

// Wait blocks until the subprocess has been reaped by Close, or ctx is done.
// Intended for tests and for orderly shutdown; it never itself terminates the
// subprocess.
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.waitDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PID reports the subprocess identifier, or 0 if it was never started.
func (s *Session) PID() int {
	if s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}
