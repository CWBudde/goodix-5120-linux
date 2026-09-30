package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/tlspsk"
	"goodix5120/internal/transport"
)

// LoopbackEC is a stand-in for the embedded controller, for rehearsing the
// bridge with no hardware attached.
//
// It is a native OpenSSL client dressed in Goodix framing. Like the EC
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
	logger *log.Logger
	client *tlspsk.Session
	conn   net.Conn // exposed only after 0xd0
	mu     sync.Mutex
	queue  [][]byte
	sent   []proto.Opcode
	closed bool
}

// LoopbackConfig configures a LoopbackEC.
type LoopbackConfig struct {
	// PSK is the key the stand-in uses. Give it the same key as the host to
	// rehearse a success, and a different one to rehearse the PSK-rejection
	// path Phase 5b might hit.
	PSK []byte
	// Logger receives progress lines. Nil means log.Default().
	Logger *log.Logger
}

// DeviceCipher is the OpenSSL name of TLS_PSK_WITH_AES_128_CBC_SHA256 (code
// point 0x00ae), the only suite the EC offers.
const DeviceCipher = tlspsk.DeviceCipher

// opRequestTLSConnection is `0xd0`. The EC answers it not with an ACK but by
// opening a TLS handshake, so it is what makes this stand-in start its client.
const opRequestTLSConnection proto.Opcode = 0xd0

// StartLoopbackEC prepares the stand-in. The TLS client itself is not started
// until `0xd0` arrives, so that, like the EC, the stand-in says nothing at all
// before it is asked for a session.
//
// That detail matters more than it looks. When the stand-in handshook at connect
// time instead, its ClientHello was already queued on the transport when the bisect
// attach step drained the device, and the bridge then waited for a hello that had
// already been thrown away.
func StartLoopbackEC(ctx context.Context, cfg LoopbackConfig) (*LoopbackEC, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	client, err := tlspsk.StartClient(ctx, tlspsk.Config{PSK: cfg.PSK})
	if err != nil {
		return nil, err
	}
	cfg.Logger.Printf("  TLS: offline EC stand-in ready; native %s; waiting for 0xd0", client.Backend())
	return &LoopbackEC{client: client, logger: cfg.Logger}, nil
}

func (e *LoopbackEC) ensureClient() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return net.ErrClosed
	}
	if e.conn == nil {
		e.conn = e.client.Device()
		e.logger.Printf("  TLS: offline EC stand-in opened its native session")
	}
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
		e.mu.Lock()
		conn := e.conn
		e.mu.Unlock()
		if conn == nil {
			return errors.New("session: TLS data before 0xd0")
		}
		if _, err := conn.Write(payload); err != nil {
			return fmt.Errorf("session: writing %d record byte(s) to the loopback EC: %w", len(payload), err)
		}
		return nil
	}

	cmd, _, err := proto.DecodeMessage(payload)
	if err != nil {
		return fmt.Errorf("session: the loopback EC could not decode a command pack: %w", err)
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return net.ErrClosed
	}
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
	conn := e.conn
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}

	if conn == nil {
		// Before 0xd0 the stand-in has nothing to say, exactly as the EC has
		// nothing to say until it is asked for a session.
		return nil, fmt.Errorf("the loopback EC has not been asked for a session yet: %w", transport.ErrTimeout)
	}
	rec, err := readRecord(conn, timeout, DefaultHostBody)
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
// the native endpoint, so they are really encrypted and really have to be decrypted
// by the host end.
func (e *LoopbackEC) SendPlaintext(b []byte) error {
	e.mu.Lock()
	active := e.conn != nil && !e.closed
	client := e.client
	e.mu.Unlock()
	if !active {
		return errors.New("session: the offline EC has no session open")
	}
	if _, err := client.Write(b); err != nil {
		return fmt.Errorf("session: encrypting offline EC plaintext: %w", err)
	}
	return nil
}

// SendEvent makes the stand-in emit an unsolicited plaintext message, queued
// behind any ACK not yet read, which is how a rehearsal simulates a
// finger-detect event after an arm. Like SendPlaintext, the caller supplies the
// bytes: the stand-in does not invent the EC's replies.
func (e *LoopbackEC) SendEvent(cmd proto.Opcode, payload []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queue = append(e.queue, proto.Encode(cmd, payload))
}

// Commands returns every opcode the stand-in was sent, in order. A rehearsal can
// assert on the sequence without the probe having to report it.
func (e *LoopbackEC) Commands() []proto.Opcode {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]proto.Opcode(nil), e.sent...)
}

// Close releases the native endpoint and wakes pending reads and writes.
func (e *LoopbackEC) Close() error {
	e.mu.Lock()
	e.closed = true
	client := e.client
	e.mu.Unlock()
	return client.Close()
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
