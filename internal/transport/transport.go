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

// frameWriter transmits one fully encoded frame. The command and payload are
// passed alongside the frame so implementations that script or assert on
// traffic (the replay fake) can inspect them without re-decoding.
type frameWriter func(ctx context.Context, cmd proto.Opcode, payload, frame []byte) error

// sender pairs the shared safety gate with a concrete frame writer. Every
// Transport in this package embeds one, which is what guarantees the USB path
// and the replay path enforce identical rules.
type sender struct {
	opts  Options
	write frameWriter
}

// Send applies the safety gate, then encodes and transmits the frame.
func (s *sender) Send(cmd proto.Opcode, payload []byte) error {
	if err := checkOpcode(cmd, s.opts.Ceiling, s.opts.Allow); err != nil {
		return err
	}

	frame := proto.Encode(cmd, payload)
	s.opts.logf("transport: TX %s (0x%02x) %d bytes: %s", cmd.Name(), byte(cmd), len(frame), hex.EncodeToString(frame))

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()
	return s.write(ctx, cmd, payload, frame)
}

// resolveTimeout picks the per-call timeout, falling back to the configured one.
func (s *sender) resolveTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return s.opts.Timeout
	}
	return timeout
}
