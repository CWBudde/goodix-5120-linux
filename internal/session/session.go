// Package session drives the device's TLS-PSK session.
//
// After `0xd0` the embedded controller opens a TLS 1.2 handshake in which **the
// EC is the client** and the host is the server (docs/protocol.md, "TLS"). Every
// record travels as the payload of a `0xb0` pack. Go's crypto/tls has no PSK
// suites, so the host end is an `openssl s_server` subprocess driven by
// internal/tlspsk; this package is the plumbing between the two:
//
//	device --0xb0 pack--> Bridge --TCP socket--> openssl (ciphertext side)
//	                                openssl --stdout--> Bridge (plaintext)
//
// The bridge is deliberately **single threaded and half duplex**: it reads from
// the device, forwards to the host, reads whatever the host has to say, and
// forwards that back, in turns. That matches how a handshake actually
// proceeds — each side speaks in flights — and it means nothing here can write
// to the USB OUT endpoint while the caller is also sending a command.
//
// Nothing in this package decrypts anything itself, and no record body is ever
// logged: on this device a body is a fingerprint image.
//
// Tier 2: this package talks to hardware only through the Device interface, and
// the one live caller is gated behind the Phase 5 flags in cmd/goodix-probe.
package session

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/tlspsk"
	"goodix5120/internal/transport"
)

// Device is the part of transport.Transport the bridge uses. It is an interface
// rather than the concrete type so a rehearsal can stand in for the EC (see
// LoopbackEC) without any USB code being linked in.
type Device interface {
	// Send transmits one command frame.
	Send(cmd proto.Opcode, payload []byte) error
	// SendTLS transmits whole TLS records as a TLS-data pack.
	SendTLS(records []byte) error
	// Recv returns one raw transfer, or an error wrapping transport.ErrTimeout
	// if the device stayed quiet.
	Recv(timeout time.Duration) ([]byte, error)
}

// Defaults applied by New for a zero Options field.
const (
	// DefaultDeviceTimeout bounds one Recv from the device. The EC answers a
	// command in single-digit milliseconds, so this is mostly about noticing
	// silence quickly.
	DefaultDeviceTimeout = 2 * time.Second
	// DefaultHostIdle is how long the local endpoint is given to start a record
	// before the bridge concludes it has nothing to say and goes back to the
	// device. openssl replies to a flight in well under a millisecond.
	DefaultHostIdle = 250 * time.Millisecond
	// DefaultHostBody bounds reading the rest of a record whose header has
	// already arrived. Those bytes are already in flight, so a timeout here is
	// a real fault rather than idleness.
	DefaultHostBody = 5 * time.Second
	// DefaultHandshakeTimeout bounds the whole handshake. The vendor driver's
	// own handshake completes in about 25 ms.
	DefaultHandshakeTimeout = 20 * time.Second
)

// Options configures a Bridge. The zero value is usable.
type Options struct {
	Logger           *log.Logger
	DeviceTimeout    time.Duration
	HostIdle         time.Duration
	HostBody         time.Duration
	HandshakeTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	if o.DeviceTimeout <= 0 {
		o.DeviceTimeout = DefaultDeviceTimeout
	}
	if o.HostIdle <= 0 {
		o.HostIdle = DefaultHostIdle
	}
	if o.HostBody <= 0 {
		o.HostBody = DefaultHostBody
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = DefaultHandshakeTimeout
	}
	return o
}

// Errors a caller is expected to distinguish. Which one comes back out of
// Handshake is the entire result of PLAN.md Phase 5b, so they are separate
// sentinels rather than one opaque failure.
var (
	// ErrHandshakeTimeout means neither side finished the handshake in time.
	ErrHandshakeTimeout = errors.New("session: TLS handshake did not complete in time")

	// ErrAlert means one side sent a TLS alert, so the handshake failed. The
	// wrapped message names the side and the alert.
	ErrAlert = errors.New("session: TLS alert")

	// ErrPSKMismatch is ErrAlert narrowed to the alerts that mean the two ends
	// derived different keys — which for a PSK suite, with no certificates in
	// play, means the pre-shared keys differ. It wraps ErrAlert, so a caller that
	// only wants to know "the handshake was rejected" can match that instead.
	//
	// INTERPRETATION, not a protocol guarantee: an alert can have other causes,
	// and no alert ever says "wrong PSK".
	ErrPSKMismatch = fmt.Errorf("%w: the device and the host do not share the same PSK", ErrAlert)
)

// Bridge forwards TLS records between a Device and a local TLS-PSK endpoint.
type Bridge struct {
	dev  Device
	sess *tlspsk.Session
	opts Options

	// hostCCS records that the host has sent its ChangeCipherSpec, which in
	// TLS 1.2 it only does after verifying the client's Finished. That is the
	// moment the PSK is known to have matched.
	hostCCS bool
	// done records that the handshake completed.
	done bool

	toHost, toDevice int // records forwarded each way

	plain plainBuf // decrypted application data, filled by one background reader
}

// New returns a Bridge over dev and sess. It takes ownership of neither: the
// caller closes both.
func New(dev Device, sess *tlspsk.Session, opts Options) *Bridge {
	return &Bridge{dev: dev, sess: sess, opts: opts.withDefaults()}
}

// Done reports whether the handshake has completed.
func (b *Bridge) Done() bool { return b.done }

// Counts reports how many records have been forwarded to the host and to the
// device. Useful in a log line; it says nothing about their contents.
func (b *Bridge) Counts() (toHost, toDevice int) { return b.toHost, b.toDevice }

// Handshake pumps records until the handshake completes, one side sends an
// alert, ctx is done or the handshake deadline passes.
//
// The caller must have sent `0xd0` and must NOT have consumed the transfers that
// followed it: the EC's ClientHello is the first thing this reads.
//
// Completion is detected on the host's ChangeCipherSpec followed by its
// Finished. In TLS 1.2 the server sends those only after verifying the client's
// Finished, which it can only do if both ends derived the same keys — so
// reaching this point *is* the answer to "does the EC accept our PSK".
func (b *Bridge) Handshake(ctx context.Context) error {
	deadline := time.Now().Add(b.opts.HandshakeTimeout)
	b.opts.Logger.Printf("  TLS: bridging the handshake — the EC is the client, openssl (pid %d, port %d) is the server",
		b.sess.PID(), b.sess.Port())

	for !b.done {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("session: handshake aborted: %w", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w after %s (%d record(s) to the host, %d to the device)",
				ErrHandshakeTimeout, b.opts.HandshakeTimeout, b.toHost, b.toDevice)
		}

		// Device → host. Silence is not a failure here: the EC speaks in
		// flights and may simply be waiting for us.
		raw, err := b.dev.Recv(b.opts.DeviceTimeout)
		switch {
		case errors.Is(err, transport.ErrTimeout):
		case err != nil:
			return fmt.Errorf("session: reading from the device: %w", err)
		default:
			if _, err := b.Deliver(raw); err != nil {
				return err
			}
		}

		// Host → device.
		if err := b.PumpHost(); err != nil {
			return err
		}
	}

	b.opts.Logger.Printf("  TLS: handshake complete — the EC and this host share the same PSK "+
		"(%d record(s) to the host, %d to the device)", b.toHost, b.toDevice)
	return nil
}

// Deliver hands the bridge one raw transfer read from the device. It reports
// whether the transfer was TLS data and was forwarded; a command message (an
// ACK, or an unsolicited finger-detect event) is left to the caller, which is
// why a false return is not an error.
func (b *Bridge) Deliver(raw []byte) (bool, error) {
	flags, payload, err := proto.DecodePack(raw)
	if err != nil {
		// Not a pack at all. The caller's own decoder logs the detail; here it
		// is simply not ours.
		return false, nil
	}
	if flags != proto.FlagTLSData && flags != proto.FlagTLSAlt {
		return false, nil
	}

	// Log and inspect the records, then forward the bytes verbatim. Records are
	// forwarded even when they do not split cleanly: TLS is a stream, the local
	// endpoint reassembles it, and a pack that holds only part of a record is
	// something we would rather see reassembled than dropped.
	if recs, err := proto.SplitTLSRecords(payload); err == nil {
		for _, r := range recs {
			b.opts.Logger.Printf("  TLS: device → host: %s", r)
			if r.Type == proto.TLSAlert {
				return true, b.alertError("the device", r.Body)
			}
		}
		b.toHost += len(recs)
	} else {
		b.opts.Logger.Printf("  TLS: device → host: %d byte(s) that are not a whole number of records (%v); forwarding anyway",
			len(payload), err)
	}

	if _, err := b.sess.Device().Write(payload); err != nil {
		return true, fmt.Errorf("session: forwarding %d byte(s) to the local endpoint: %w", len(payload), err)
	}
	return true, nil
}

// PumpHost forwards every record the local endpoint has ready to the device and
// returns once it has nothing more to say.
func (b *Bridge) PumpHost() error {
	for {
		rec, err := b.readHostRecord()
		if errors.Is(err, errHostIdle) {
			return nil
		}
		if err != nil {
			return err
		}

		typ := rec[0]
		b.opts.Logger.Printf("  TLS: host → device: %s", proto.DescribeTLSRecord(rec))
		if typ == proto.TLSAlert {
			// A plaintext alert during the handshake carries a readable level
			// and description; once the session is encrypted it does not, and
			// the body is reported as opaque.
			if err := b.alertError("the host", rec[proto.TLSRecordHeaderLen:]); err != nil {
				return err
			}
		}

		if err := b.dev.SendTLS(rec); err != nil {
			return fmt.Errorf("session: sending a %s record to the device: %w", proto.TLSTypeName(typ), err)
		}
		b.toDevice++

		switch {
		case typ == proto.TLSChangeCipherSpec:
			b.hostCCS = true
		case typ == proto.TLSHandshake && b.hostCCS:
			// Change cipher spec then Finished: the host has verified the EC's
			// Finished, so the handshake is up.
			b.done = true
			return nil
		}
	}
}

// errHostIdle means the local endpoint had no record ready. It never leaves this
// package.
var errHostIdle = errors.New("session: local endpoint idle")

// readHostRecord reads one whole TLS record from the ciphertext side of the local
// endpoint, or reports errHostIdle if none was started within HostIdle.
func (b *Bridge) readHostRecord() ([]byte, error) {
	rec, err := readRecord(b.sess.Device(), b.opts.HostIdle, b.opts.HostBody)
	if err != nil && !errors.Is(err, errHostIdle) {
		return nil, fmt.Errorf("session: on the local endpoint (openssl): %w", err)
	}
	return rec, err
}

// ReadApplicationData reads one burst of decrypted application data.
//
// It does two things in turn until the plaintext settles: forward whatever the
// device has to the host, and check what the host has decrypted. Interleaving is
// necessary because an image only becomes plaintext once its ciphertext has been
// forwarded, and half duplex is what keeps this off the caller's own use of the
// device.
//
// It reads until quiet rather than to a fixed length on purpose. The plaintext
// length of an image is not known: the record is 7744 bytes, which bounds the
// plaintext at 7680..7695 depending on CBC padding (docs/protocol.md, "How big
// is an image, really"), and measuring it is the point of Phase 5c. max is a
// ceiling, not an expectation; ctx bounds the whole call.
func (b *Bridge) ReadApplicationData(ctx context.Context, idle time.Duration, max int) ([]byte, error) {
	if idle <= 0 {
		idle = DefaultPlaintextIdle
	}
	if max <= 0 {
		return nil, errors.New("session: ReadApplicationData needs a positive maximum")
	}
	b.startPlaintextReader()

	for {
		if err := ctx.Err(); err != nil {
			if got, _, _ := b.plain.status(); got > 0 {
				// Whatever arrived is still the measurement, and saying so beats
				// discarding it because the deadline was tight.
				b.opts.Logger.Printf("  TLS: %v with %d plaintext byte(s) in hand; returning those", err, got)
				return b.plain.take(max)
			}
			return nil, fmt.Errorf("session: reading application data: %w", err)
		}

		// Device → host.
		raw, err := b.dev.Recv(b.opts.DeviceTimeout)
		switch {
		case errors.Is(err, transport.ErrTimeout):
		case err != nil:
			return nil, fmt.Errorf("session: reading from the device: %w", err)
		default:
			if _, err := b.Deliver(raw); err != nil {
				return nil, err
			}
		}

		// Has the plaintext settled?
		got, quiet, rerr := b.plain.status()
		switch {
		case got >= max:
			return b.plain.take(max)
		case got > 0 && (quiet >= idle || rerr != nil):
			return b.plain.take(max)
		case got == 0 && rerr != nil:
			return nil, fmt.Errorf("session: the local endpoint stopped producing plaintext: %w", rerr)
		}
	}
}

// DefaultPlaintextIdle is how long the plaintext stream must be quiet before
// ReadApplicationData calls a burst complete.
const DefaultPlaintextIdle = 400 * time.Millisecond

// startPlaintextReader starts the one goroutine that drains the local endpoint's
// plaintext side. It runs for the life of the bridge: the read it is blocked in
// is released when the caller closes the tlspsk session, which tears down the
// subprocess and with it the pipe.
func (b *Bridge) startPlaintextReader() {
	b.plain.mu.Lock()
	defer b.plain.mu.Unlock()
	if b.plain.started {
		return
	}
	b.plain.started = true
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := b.sess.Read(buf)
			b.plain.mu.Lock()
			if n > 0 {
				b.plain.buf = append(b.plain.buf, buf[:n]...)
				b.plain.last = time.Now()
			}
			if err != nil {
				b.plain.err = err
				b.plain.mu.Unlock()
				return
			}
			b.plain.mu.Unlock()
		}
	}()
}

// plainBuf accumulates decrypted application data off the reader goroutine.
type plainBuf struct {
	mu      sync.Mutex
	buf     []byte
	last    time.Time
	err     error
	started bool
}

// status reports how much plaintext is buffered, how long it has been since the
// last byte arrived, and whether the reader has finished.
func (p *plainBuf) status() (n int, quiet time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) == 0 {
		return 0, 0, p.err
	}
	return len(p.buf), time.Since(p.last), p.err
}

// take removes and returns up to max buffered bytes.
func (p *plainBuf) take(max int) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := min(len(p.buf), max)
	out := p.buf[:n:n]
	p.buf = p.buf[n:]
	return out, nil
}

// alertError turns a TLS alert into the error the caller acts on. side is the
// sender, for the message.
func (b *Bridge) alertError(side string, body []byte) error {
	// A plaintext alert body is [level][description]. An encrypted one is longer
	// and unreadable, which is itself worth saying.
	if len(body) != 2 {
		return fmt.Errorf("%w: %s sent an encrypted %d-byte alert, so its reason is not readable here",
			ErrAlert, side, len(body))
	}
	level, desc := body[0], body[1]
	if level == 1 && desc == alertCloseNotify {
		return fmt.Errorf("%w: %s closed the session (close_notify)", ErrAlert, side)
	}

	err := ErrAlert
	if keyMismatchAlerts[desc] {
		err = ErrPSKMismatch
	}
	return fmt.Errorf("%w: %s sent a %s alert: %s (0x%02x)", err, side, alertLevelName(level), alertName(desc), desc)
}

// TLS alert descriptions (RFC 5246 §7.2), named only where this project could
// plausibly see them.
const (
	alertCloseNotify       byte = 0
	alertUnexpectedMessage byte = 10
	alertBadRecordMAC      byte = 20
	alertHandshakeFailure  byte = 40
	alertIllegalParameter  byte = 47
	alertDecodeError       byte = 50
	alertDecryptError      byte = 51
	alertProtocolVersion   byte = 70
	alertInsufficientSec   byte = 71
	alertInternalError     byte = 80
	alertUnknownPSKID      byte = 115
)

// keyMismatchAlerts are the alerts that mean the two ends derived different keys.
// With a PSK suite and no certificates involved, that means the pre-shared keys
// differ — which is the one answer Phase 5b exists to get.
var keyMismatchAlerts = map[byte]bool{
	alertBadRecordMAC:     true,
	alertHandshakeFailure: true,
	alertDecryptError:     true,
	alertUnknownPSKID:     true,
}

func alertName(desc byte) string {
	switch desc {
	case alertCloseNotify:
		return "close_notify"
	case alertUnexpectedMessage:
		return "unexpected_message"
	case alertBadRecordMAC:
		return "bad_record_mac"
	case alertHandshakeFailure:
		return "handshake_failure"
	case alertIllegalParameter:
		return "illegal_parameter"
	case alertDecodeError:
		return "decode_error"
	case alertDecryptError:
		return "decrypt_error"
	case alertProtocolVersion:
		return "protocol_version"
	case alertInsufficientSec:
		return "insufficient_security"
	case alertInternalError:
		return "internal_error"
	case alertUnknownPSKID:
		return "unknown_psk_identity"
	default:
		return "unnamed alert"
	}
}

func alertLevelName(level byte) string {
	switch level {
	case 1:
		return "warning"
	case 2:
		return "fatal"
	default:
		return fmt.Sprintf("level-%d", level)
	}
}
