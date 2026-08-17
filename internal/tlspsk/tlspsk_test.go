package tlspsk

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(DefaultOpenSSL); err != nil {
		t.Skip("openssl not on PATH; skipping subprocess test")
	}
}

// testConfig asks for an ephemeral port so parallel runs cannot collide on
// 4433.
func testConfig() Config {
	return Config{PSK: ReferencePSK(), Port: -1, Timeout: 5 * time.Second}
}

// processAlive reports whether pid names a live, non-zombie process.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	// Signal 0 also succeeds for zombies, so check the state field in
	// /proc/<pid>/stat. The state is the char after the final ")".
	stat, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	i := strings.LastIndex(string(stat), ")")
	if i < 0 || i+2 >= len(stat) {
		return false
	}
	return stat[i+2] != 'Z'
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func waitGone(t *testing.T, pid int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d still alive after %s", pid, d)
}

func TestReferencePSK(t *testing.T) {
	psk := ReferencePSK()
	if len(psk) != 32 {
		t.Fatalf("ReferencePSK length = %d, want 32", len(psk))
	}
	for i, b := range psk {
		if b != 0 {
			t.Fatalf("ReferencePSK[%d] = 0x%02x, want 0x00", i, b)
		}
	}
	if hex.EncodeToString(psk) != ReferencePSKHex {
		t.Fatal("ReferencePSK does not round-trip ReferencePSKHex")
	}
	// Mutating the returned slice must not affect later callers.
	psk[0] = 0xff
	if ReferencePSK()[0] != 0x00 {
		t.Fatal("ReferencePSK returns shared state")
	}
}

func TestStartRejectsEmptyPSK(t *testing.T) {
	_, err := Start(context.Background(), Config{Port: -1})
	if err == nil {
		t.Fatal("expected an error for an empty PSK")
	}
}

func TestStartMissingOpenSSL(t *testing.T) {
	cfg := testConfig()
	cfg.OpenSSL = "openssl-definitely-not-installed-xyzzy"
	_, err := Start(context.Background(), cfg)
	if !errors.Is(err, ErrOpenSSLMissing) {
		t.Fatalf("got %v, want ErrOpenSSLMissing", err)
	}
	if !strings.Contains(err.Error(), "install") {
		t.Fatalf("error should name what to install, got: %v", err)
	}
}

func TestDefaultsApplied(t *testing.T) {
	got := Config{}.withDefaults()
	if got.Port != DefaultPort || got.OpenSSL != DefaultOpenSSL || got.Timeout != DefaultTimeout {
		t.Fatalf("withDefaults() = %+v", got)
	}
	if DefaultPort != 4433 {
		t.Fatalf("DefaultPort = %d, want 4433 (upstream driver_51x0.py)", DefaultPort)
	}
}

func TestStartAndCloseLeavesNoChild(t *testing.T) {
	requireOpenSSL(t)

	s, err := Start(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := s.PID()
	if pid == 0 {
		t.Fatal("PID() = 0 after a successful Start")
	}
	if !processAlive(pid) {
		t.Fatalf("subprocess %d is not alive right after Start", pid)
	}
	if s.Port() <= 0 {
		t.Fatalf("Port() = %d", s.Port())
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if processAlive(pid) {
		t.Fatalf("subprocess %d survived Close", pid)
	}
}

func TestDoubleCloseIsSafe(t *testing.T) {
	requireOpenSSL(t)

	s, err := Start(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := s.PID()

	first := s.Close()
	second := s.Close()
	if first != nil {
		t.Fatalf("first Close: %v", first)
	}
	if second != first {
		t.Fatalf("second Close = %v, want the first result %v", second, first)
	}
	// And a third, for good measure.
	if third := s.Close(); third != first {
		t.Fatalf("third Close = %v", third)
	}
	if processAlive(pid) {
		t.Fatalf("subprocess %d survived Close", pid)
	}
}

func TestContextCancellationTearsDownSubprocess(t *testing.T) {
	requireOpenSSL(t)

	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, testConfig())
	if err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	pid := s.PID()
	if !processAlive(pid) {
		t.Fatalf("subprocess %d is not alive right after Start", pid)
	}

	cancel()
	waitGone(t, pid, 5*time.Second)

	wctx, wcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wcancel()
	if err := s.Wait(wctx); err != nil {
		t.Fatalf("Wait after cancellation: %v", err)
	}
	// Close after the context already tore things down must still be safe.
	if err := s.Close(); err != nil {
		t.Fatalf("Close after cancellation: %v", err)
	}
}

func TestReadWriteAfterClose(t *testing.T) {
	requireOpenSSL(t)

	s, err := Start(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close should fail")
	}
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read after Close should fail")
	}
}

// End-to-end: a real TLS-PSK handshake must complete and application data must
// cross the endpoint. The device side is stood in for by `openssl s_client`,
// which speaks the ciphertext half; Session.Read/Write is the plaintext half.
//
// This is also the check that the plaintext/ciphertext directions are not
// inverted: the socket carries TLS records, the pipes carry application data.
func TestEndToEndPSKHandshake(t *testing.T) {
	requireOpenSSL(t)

	s, err := Start(context.Background(), testConfig())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Stand-in for the fingerprint sensor: s_client speaks TLS-PSK, and the
	// test relays its records through Session.Device() exactly as the real
	// driver will relay the sensor's records. s_client connects to a throwaway
	// listener owned by the test rather than straight to the openssl server,
	// because s_server serves one connection at a time and Session already
	// holds it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		} else {
			close(accepted)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, DefaultOpenSSL, "s_client",
		"-psk", ReferencePSKHex,
		"-connect", ln.Addr().String(),
		"-quiet",
	)
	clientIn, err := client.StdinPipe()
	if err != nil {
		t.Fatalf("client stdin: %v", err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("starting s_client: %v", err)
	}
	defer func() {
		_ = clientIn.Close()
		_ = client.Process.Kill()
		_ = client.Wait()
	}()

	var deviceConn net.Conn
	select {
	case c, ok := <-accepted:
		if !ok {
			t.Fatal("accept failed")
		}
		deviceConn = c
	case <-time.After(10 * time.Second):
		t.Fatal("s_client never connected")
	}
	defer func() { _ = deviceConn.Close() }()

	// Bridge ciphertext in both directions.
	go func() { _, _ = io.Copy(s.Device(), deviceConn) }()
	go func() { _, _ = io.Copy(deviceConn, s.Device()) }()

	const msg = "hello-plaintext\n"
	// Give the handshake a moment, then send application data.
	time.Sleep(500 * time.Millisecond)
	if _, err := clientIn.Write([]byte(msg)); err != nil {
		t.Fatalf("writing to s_client: %v", err)
	}

	type result struct {
		s   string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, len(msg))
		n, err := io.ReadFull(s, buf)
		ch <- result{string(buf[:n]), err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("reading plaintext: %v (got %q)", r.err, r.s)
		}
		if r.s != msg {
			t.Fatalf("plaintext = %q, want %q", r.s, msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for decrypted plaintext")
	}
}
