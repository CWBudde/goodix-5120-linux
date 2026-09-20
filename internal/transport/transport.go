// Package transport carries encoded protocol frames to and from the Goodix
// 27c6:5120 fingerprint sensor.
//
// The package deliberately does more than move bytes: it is the single
// enforcement point for command safety. The sensor can be permanently bricked
// by firmware-write commands, so every outbound command passes through one
// shared gate (checkOpcode) that refuses unregistered opcodes and any opcode
// whose class exceeds the configured ceiling. Both the real USB transport and
// the scripted replay fake route their Send through that same gate, so the two
// cannot drift apart.
package transport

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"goodix5120/internal/proto"
)

// DefaultTimeout is used for a transfer when Options.Timeout is zero.
const DefaultTimeout = 5 * time.Second

// Transport is a bidirectional channel to the sensor.
type Transport interface {
	// Send encodes cmd/payload into a wire frame and transmits it. It returns
	// an error without transmitting anything if the command is not permitted
	// by the configured safety ceiling.
	Send(cmd proto.Opcode, payload []byte) error

	// SendTLS transmits whole TLS records as the payload of a TLS-data pack.
	// This is the reverse direction of the records the device sends after
	// `0xd0`, and it carries no opcode, so the class ceiling has nothing to
	// classify: the path is refused outright unless Options.AllowTLSData is
	// set. Records must be complete — see checkTLSData.
	SendTLS(records []byte) error

	// Recv returns the raw bytes read from the IN endpoint. A short read is
	// normal and is not an error. A zero timeout means "use Options.Timeout".
	// If nothing arrives in time the error wraps ErrTimeout.
	Recv(timeout time.Duration) ([]byte, error)

	// Close releases all resources. It is safe to call more than once.
	Close() error
}

// Options configures a Transport.
type Options struct {
	// Ceiling is the highest command class that may be transmitted. Any Send
	// of an opcode above this class is refused. The zero value is
	// proto.ClassSafe, i.e. read-only commands only.
	Ceiling proto.Class

	// Allow names registered opcodes that may be transmitted although their
	// class is above Ceiling. It is an exact, per-opcode exception for one
	// deliberate experiment (confirming that preset_psk_read wedges the EC). It
	// never admits an unregistered or a destructive opcode. Nil admits nothing.
	Allow []proto.Opcode

	// AllowTLSData opens the raw TLS data path, i.e. SendTLS. It is off by
	// default, so a caller that has no business bridging a TLS session cannot
	// put opaque bytes on the wire by accident.
	//
	// It is deliberately a separate switch rather than a Ceiling value or an
	// Allow entry: a TLS-data pack carries no opcode, so there is no class to
	// compare and no registry entry to look up. What the gate can still check
	// is that the caller asked for this path and that the bytes are whole TLS
	// records; both are checked in checkTLSData.
	AllowTLSData bool

	// Timeout bounds a single transfer. Zero means DefaultTimeout.
	Timeout time.Duration

	// Verbose logs every transfer as hex to Logger.
	Verbose bool

	// Logger receives verbose transfer logs. Nil means log.Default().
	Logger *log.Logger
}

// withDefaults returns a copy of o with zero fields filled in.
func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	return o
}

// logf writes a verbose message if verbose logging is enabled.
func (o Options) logf(format string, args ...any) {
	if !o.Verbose {
		return
	}
	o.Logger.Printf(format, args...)
}

// maxDump is how many bytes of a transfer a verbose log line may contain.
//
// It is a cap rather than a nicety. Once the TLS session is up, an inbound
// transfer is a 7749-byte pack holding an encrypted fingerprint image, and
// `--bisect` turns verbose logging on unconditionally. The header and the first
// bytes are what a human reads; the rest only fills the log with ciphertext of
// biometric data.
const maxDump = 64

// dump renders a transfer for a log line, truncated to maxDump bytes.
func dump(b []byte) string {
	if len(b) <= maxDump {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s… (%d more byte(s))", hex.EncodeToString(b[:maxDump]), len(b)-maxDump)
}

// ErrRefused is the classification sentinel for a command the safety gate
// declined to transmit, whether because the opcode is unregistered or because
// its class exceeds the ceiling. Every refusal wraps it, so callers can match
// with errors.Is instead of inspecting message text. The wrapped message
// carries the specific reason.
var ErrRefused = errors.New("command refused by the transport safety gate")

// ErrTimeout reports that the device sent nothing before a Recv timed out. It
// is the normal way to learn that the device has gone quiet, so callers match
// it with errors.Is rather than treating it as a failure.
var ErrTimeout = errors.New("no data before the receive timeout")

// checkOpcode is the single safety gate shared by every Transport
// implementation. It reports why cmd may not be transmitted under ceiling and
// allow, or nil if transmitting it is permitted.
//
// Three rules, in order:
//  1. An opcode not registered in the proto command table is refused outright.
//     An unknown byte has unknown consequences, so it is never passed through.
//  2. A destructive opcode above the ceiling is refused, whatever allow says.
//  3. Any other opcode above the ceiling is refused unless allow names it.
func checkOpcode(cmd proto.Opcode, ceiling proto.Class, allow []proto.Opcode) error {
	class, ok := cmd.Class()
	if !ok {
		return fmt.Errorf("%w: unregistered opcode 0x%02x is not in the proto command table, so its effect on the device is unknown", ErrRefused, byte(cmd))
	}
	if class > ceiling && (class >= proto.ClassDestructive || !slices.Contains(allow, cmd)) {
		return fmt.Errorf("%w: %s (0x%02x) is %s, which exceeds the configured ceiling %s", ErrRefused, cmd.Name(), byte(cmd), class, ceiling)
	}
	return nil
}

// checkPayload is the second half of the safety gate. An opcode's registered
// PayloadRule records what the vendor driver was observed to send; a payload
// that violates it is a frame no working driver has ever produced.
//
// The one such frame whose effect is known is 0xe4 with an empty payload. It
// wedged the embedded controller and killed the laptop's internal keyboard in
// Runs 1, 2 and 4 (docs/protocol.md), and Run 4 sent it alone, so nothing else
// is required to trigger it. The vendor's 0xe4 carrying eight bytes is answered
// normally in all nine complete driver inits.
func checkPayload(cmd proto.Opcode, payload []byte) error {
	if err := cmd.CheckPayload(len(payload)); err != nil {
		return fmt.Errorf("%w: %s (0x%02x) rejected: %w", ErrRefused, cmd.Name(), byte(cmd), err)
	}
	return nil
}

// checkTLSData is the gate for the raw TLS data path. A TLS-data pack has no
// opcode, so there is no class and no payload rule to consult; what can be
// checked is checked.
//
// Two rules:
//  1. The path is off unless the caller asked for it. Bridging a TLS session is
//     a deliberate act (PLAN.md Phase 5b), not something a probe does in
//     passing, and an opaque byte path with no opcode deserves its own switch.
//  2. The buffer must hold whole TLS records and nothing else. Half a record is
//     a frame no working driver produces, and this project has one hard-won
//     rule about frames like that: an 0xe4 whose argument was missing wedged
//     the EC and killed the keyboard three times. A truncated record is the same
//     shape of mistake, so it is refused here rather than sent and puzzled over.
func checkTLSData(records []byte, allowed bool) error {
	if !allowed {
		return fmt.Errorf("%w: the raw TLS data path is closed; set Options.AllowTLSData to bridge TLS records to the device", ErrRefused)
	}
	if len(records) == 0 {
		return fmt.Errorf("%w: refusing to send an empty TLS-data pack", ErrRefused)
	}
	if _, err := proto.SplitTLSRecords(records); err != nil {
		return fmt.Errorf("%w: TLS data is not a whole number of records: %w", ErrRefused, err)
	}
	return nil
}

// check is the full gate: class first, then payload, so a refusal names the
// most serious reason. It is deliberately the only way into the frame writers.
//
// The gate lives here, in sender, rather than in the probe's step table,
// because the frame that wedged the EC was not built from the step table:
// runBisect called Send directly. A rule in a caller is advice; a rule here is
// enforced for the USB path and the replay path alike, which is what lets an
// offline test prove something about the live path.
func check(cmd proto.Opcode, payload []byte, ceiling proto.Class, allow []proto.Opcode) error {
	if err := checkOpcode(cmd, ceiling, allow); err != nil {
		return err
	}
	return checkPayload(cmd, payload)
}

// outbound is one thing to transmit. The decoded command and payload travel
// alongside the encoded frame so implementations that script or assert on
// traffic (the replay fake) can inspect them without re-decoding.
type outbound struct {
	// frame is the fully encoded pack, ready for the wire.
	frame []byte

	// tls reports that this is a TLS-data pack rather than a command. When it
	// is true cmd is meaningless and payload holds the raw TLS records.
	tls bool

	cmd     proto.Opcode
	payload []byte
}

// frameWriter transmits one fully encoded frame.
type frameWriter func(ctx context.Context, out outbound) error

// sender pairs the shared safety gate with a concrete frame writer. Every
// Transport in this package embeds one, which is what guarantees the USB path
// and the replay path enforce identical rules.
type sender struct {
	opts  Options
	write frameWriter
}

// Send applies the safety gate, then encodes and transmits the frame.
func (s *sender) Send(cmd proto.Opcode, payload []byte) error {
	if err := check(cmd, payload, s.opts.Ceiling, s.opts.Allow); err != nil {
		return err
	}

	frame := proto.Encode(cmd, payload)
	s.opts.logf("transport: TX %s (0x%02x) %d bytes: %s", cmd.Name(), byte(cmd), len(frame), dump(frame))

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()
	return s.write(ctx, outbound{frame: frame, cmd: cmd, payload: payload})
}

// SendTLS applies the TLS-data half of the gate, then wraps the records in a
// pack and transmits it.
//
// The bytes are logged by record header only — type, version and length. A
// record body from this device is a fingerprint image, and the host's own
// handshake records are derived from the PSK, so neither is hex-dumped even
// under Options.Verbose.
func (s *sender) SendTLS(records []byte) error {
	if err := checkTLSData(records, s.opts.AllowTLSData); err != nil {
		return err
	}

	frame := proto.EncodePack(proto.FlagTLSData, records)
	if recs, err := proto.SplitTLSRecords(records); err == nil {
		for _, r := range recs {
			s.opts.logf("transport: TX TLS %s", r)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()
	return s.write(ctx, outbound{frame: frame, tls: true, payload: records})
}

// resolveTimeout picks the per-call timeout, falling back to the configured one.
func (s *sender) resolveTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return s.opts.Timeout
	}
	return timeout
}
