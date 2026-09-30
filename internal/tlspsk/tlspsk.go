// Package tlspsk implements the fixed Goodix TLS 1.2 PSK endpoint in-process.
package tlspsk

/*
#cgo pkg-config: openssl
#include "native.h"
*/
import "C"

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"
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

const (
	DeviceCipher = "PSK-AES128-CBC-SHA256"
	Identity     = "Client_identity"
	QueueLimit   = 64 * 1024
)

var (
	ErrPolicy      = errors.New("tlspsk: effective OpenSSL policy rejects the device TLS suite")
	ErrPSKMismatch = errors.New("tlspsk: likely PSK mismatch")
	ErrTLS         = errors.New("tlspsk: TLS endpoint failure")
	ErrOverflow    = errors.New("tlspsk: bounded queue overflow")
)

// Config fixes the protocol to TLS 1.2, 0x00ae and Client_identity.
// Startup performs no network I/O. Context cancellation controls its lifetime.
type Config struct {
	PSK []byte
}

// Preflight checks real server selection under the process's effective system
// policy, with a disposable SSL and synthetic device-shaped ClientHello.
func Preflight(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nativeError(int(C.g5120_preflight()))
}

func nativeError(code int) error {
	switch code {
	case 0:
		return nil
	case -2:
		return ErrPolicy
	case -3:
		return ErrPSKMismatch
	case -4:
		return ErrOverflow
	case -5:
		return io.EOF
	default:
		return ErrTLS
	}
}

// Session serializes all SSL operations and owns C-allocated key material.
// Device is an in-memory ciphertext connection; Read/Write carry plaintext.
type Session struct {
	mu                          sync.Mutex
	native                      *C.g5120_endpoint
	cipher, plain               []byte
	changed                     chan struct{}
	done                        chan struct{}
	err                         error
	ready                       bool
	readDeadline, writeDeadline time.Time
	device                      memoryConn
}

func Start(ctx context.Context, cfg Config) (*Session, error) { return start(ctx, cfg, false) }

// StartClient is the offline rehearsal peer. It emits its ClientHello on Device.
func StartClient(ctx context.Context, cfg Config) (*Session, error) { return start(ctx, cfg, true) }

func start(ctx context.Context, cfg Config, client bool) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(cfg.PSK) != PSKLen {
		return nil, fmt.Errorf("tlspsk: PSK has %d bytes, want %d", len(cfg.PSK), PSKLen)
	}
	var code C.int
	var role C.int
	if client {
		role = 1
	}
	// The native constructor copies these bytes; it retains no Go pointer.
	native := C.g5120_new((*C.uchar)(unsafe.Pointer(&cfg.PSK[0])), role, &code)
	if native == nil {
		return nil, nativeError(int(code))
	}
	s := &Session{native: native, changed: make(chan struct{}), done: make(chan struct{}),
		cipher: make([]byte, 0, QueueLimit), plain: make([]byte, 0, QueueLimit)}
	s.device.s = s
	s.mu.Lock()
	err := s.driveLocked()
	s.mu.Unlock()
	if err != nil {
		s.Close()
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.failLocked(ctx.Err())
			s.mu.Unlock()
		case <-s.done:
		}
	}()
	return s, nil
}

func (s *Session) signalLocked() { close(s.changed); s.changed = make(chan struct{}) }

func (s *Session) failLocked(err error) {
	if s.err != nil {
		return
	}
	s.err = err
	clear(s.plain)
	clear(s.cipher)
	s.plain = nil
	s.cipher = nil
	C.g5120_free(s.native)
	s.native = nil
	close(s.done)
	s.signalLocked()
}

func (s *Session) drainLocked() error {
	var buf [4096]byte
	for {
		n := int(C.g5120_drain(s.native, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
		if n < 0 {
			return nativeError(n)
		}
		if n == 0 {
			return nil
		}
		if len(s.cipher)+n > QueueLimit {
			return ErrOverflow
		}
		s.cipher = append(s.cipher, buf[:n]...)
	}
}

func (s *Session) driveLocked() error {
	var buf [4096]byte
	for {
		n := int(C.g5120_step(s.native, (*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))))
		err := s.drainLocked()
		if err == nil && n < 0 {
			err = nativeError(n)
		}
		if err != nil {
			s.failLocked(err)
			return err
		}
		s.ready = C.g5120_ready(s.native) != 0
		if n > 0 {
			if len(s.plain)+n > QueueLimit {
				s.failLocked(ErrOverflow)
				return ErrOverflow
			}
			s.plain = append(s.plain, buf[:n]...)
		}
		s.signalLocked()
		if n == 0 {
			return nil
		}
	}
}

// waitLocked drops the SSL mutex while waiting and rechecks changed deadlines
// after every notification. Close, cancellation and deadline changes wake it.
func (s *Session) waitLocked(deadline time.Time) error {
	changed := s.changed
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(time.Until(deadline))
		timeout = timer.C
	}
	s.mu.Unlock()
	var err error
	select {
	case <-changed:
	case <-timeout:
		err = os.ErrDeadlineExceeded
	}
	if timer != nil {
		timer.Stop()
	}
	s.mu.Lock()
	return err
}

func (s *Session) Read(p []byte) (int, error) { return s.read(p, false) }
func (s *Session) read(p []byte, cipher bool) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		queue := &s.plain
		var deadline time.Time
		if cipher {
			queue = &s.cipher
			deadline = s.readDeadline
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(*queue) > 0 {
			n := copy(p, *queue)
			remaining := copy(*queue, (*queue)[n:])
			clear((*queue)[remaining:])
			*queue = (*queue)[:remaining]
			return n, nil
		}
		if s.err != nil {
			return 0, s.err
		}
		if err := s.waitLocked(deadline); err != nil {
			return 0, err
		}
	}
}

func (s *Session) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for !s.ready && s.err == nil {
		if err := s.waitLocked(time.Time{}); err != nil {
			return 0, err
		}
	}
	if s.err != nil {
		return 0, s.err
	}
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), 16384)]
		n := int(C.g5120_write(s.native, (*C.uchar)(unsafe.Pointer(&chunk[0])), C.size_t(len(chunk))))
		err := s.drainLocked()
		if err == nil && n <= 0 {
			err = nativeError(n)
			if err == nil {
				err = ErrTLS
			}
		}
		if err != nil {
			s.failLocked(err)
			return written, err
		}
		written += n
		p = p[n:]
		s.signalLocked()
	}
	return written, nil
}

func (s *Session) Device() net.Conn { return &s.device }
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(net.ErrClosed)
	return nil
}
func (s *Session) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Backend describes the library and fixed parameters without secrets.
func (s *Session) Backend() string {
	return C.GoString(C.g5120_version()) + "; TLS 1.2; " + DeviceCipher
}

type memoryConn struct{ s *Session }

func (c *memoryConn) Read(p []byte) (int, error) { return c.s.read(p, true) }
func (c *memoryConn) Write(p []byte) (int, error) {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) == 0 {
		return 0, nil
	}
	err := nativeError(int(C.g5120_feed(s.native, (*C.uchar)(unsafe.Pointer(&p[0])), C.size_t(len(p)))))
	if err != nil {
		s.failLocked(err)
		return 0, err
	}
	if err = s.driveLocked(); err != nil {
		return len(p), err
	}
	return len(p), nil
}
func (c *memoryConn) Close() error { return c.s.Close() }

type memoryAddr struct{}

func (memoryAddr) Network() string         { return "memory" }
func (memoryAddr) String() string          { return "goodix-tls" }
func (c *memoryConn) LocalAddr() net.Addr  { return memoryAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr { return memoryAddr{} }
func (c *memoryConn) SetDeadline(t time.Time) error {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.readDeadline = t
	s.writeDeadline = t
	s.signalLocked()
	return nil
}
func (c *memoryConn) SetReadDeadline(t time.Time) error {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.readDeadline = t
	s.signalLocked()
	return nil
}
func (c *memoryConn) SetWriteDeadline(t time.Time) error {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.writeDeadline = t
	s.signalLocked()
	return nil
}
