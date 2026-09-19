package transport

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"goodix5120/internal/proto"
)

// Opcodes used throughout these tests. They must stay in sync with the proto
// registry; the guard test below fails loudly if their classes ever change.
const (
	opNOP    proto.Opcode = 0x00 // safe
	opReset  proto.Opcode = 0xa2 // state-changing
	opFWVer  proto.Opcode = 0xa8 // safe
	opUnknwn proto.Opcode = 0x7b // deliberately unregistered
)

func TestOpcodeFixturesMatchProtoRegistry(t *testing.T) {
	for _, tc := range []struct {
		op    proto.Opcode
		want  proto.Class
		known bool
	}{
		{opNOP, proto.ClassSafe, true},
		{opFWVer, proto.ClassSafe, true},
		{opReset, proto.ClassStateChanging, true},
		{opUnknwn, 0, false},
	} {
		got, ok := tc.op.Class()
		if ok != tc.known {
			t.Fatalf("opcode 0x%02x: registered=%v, want %v", byte(tc.op), ok, tc.known)
		}
		if ok && got != tc.want {
			t.Fatalf("opcode 0x%02x: class %v, want %v", byte(tc.op), got, tc.want)
		}
	}
}

// stubWriter records every frame handed to it, standing in for the USB OUT
// endpoint.
type stubWriter struct {
	frames [][]byte
	cmds   []proto.Opcode
	err    error
}

func (w *stubWriter) write(_ context.Context, cmd proto.Opcode, _, frame []byte) error {
	if w.err != nil {
		return w.err
	}
	w.cmds = append(w.cmds, cmd)
	w.frames = append(w.frames, append([]byte(nil), frame...))
	return nil
}

// newStubTransport builds a sender wired to a recording writer, exercising the
// exact code path the USB transport uses for Send.
func newStubTransport(opts Options) (*sender, *stubWriter) {
	w := &stubWriter{}
	return &sender{opts: opts.withDefaults(), write: w.write}, w
}

// This is the central safety requirement: a state-changing opcode must be
// refused under the default (safe) ceiling, and nothing may reach the wire.
func TestSendRefusesStateChangingUnderDefaultCeiling(t *testing.T) {
	s, w := newStubTransport(Options{}) // zero value => ClassSafe ceiling

	err := s.Send(opReset, []byte{0x01})
	if err == nil {
		t.Fatal("Send(reset) succeeded under the default safe ceiling; it must be refused")
	}
	for _, want := range []string{"reset", "state-changing", "safe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	if len(w.frames) != 0 {
		t.Fatalf("refused command still wrote %d frame(s) to the device: %x", len(w.frames), w.frames)
	}
}

func TestSendRefusesUnregisteredOpcode(t *testing.T) {
	// Even a maximally permissive ceiling must not let an unknown opcode out.
	s, w := newStubTransport(Options{Ceiling: proto.ClassDestructive})

	err := s.Send(opUnknwn, nil)
	if err == nil {
		t.Fatal("Send of an unregistered opcode succeeded; it must be refused")
	}
	if !strings.Contains(err.Error(), "unregistered") {
		t.Errorf("error %q does not explain that the opcode is unregistered", err)
	}
	if len(w.frames) != 0 {
		t.Fatalf("refused command still wrote %d frame(s): %x", len(w.frames), w.frames)
	}
}

func TestSendTransmitsWithinCeiling(t *testing.T) {
	s, w := newStubTransport(Options{Ceiling: proto.ClassStateChanging})

	payload := []byte{0xde, 0xad}
	if err := s.Send(opReset, payload); err != nil {
		t.Fatalf("Send(reset) under a state-changing ceiling: %v", err)
	}
	if err := s.Send(opNOP, nil); err != nil {
		t.Fatalf("Send(nop): %v", err)
	}

	if got, want := len(w.frames), 2; got != want {
		t.Fatalf("wrote %d frames, want %d", got, want)
	}
	if want := proto.Encode(opReset, payload); !bytes.Equal(w.frames[0], want) {
		t.Errorf("frame 0 = %x, want %x", w.frames[0], want)
	}
	if want := proto.Encode(opNOP, nil); !bytes.Equal(w.frames[1], want) {
		t.Errorf("frame 1 = %x, want %x", w.frames[1], want)
	}
}

func TestSendPropagatesWriterError(t *testing.T) {
	s, w := newStubTransport(Options{})
	w.err = errors.New("endpoint stalled")

	if err := s.Send(opNOP, nil); !strings.Contains(err.Error(), "endpoint stalled") {
		t.Fatalf("Send error = %v, want it to wrap the writer error", err)
	}
}

func TestCheckOpcodeCeilings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		op      proto.Opcode
		ceiling proto.Class
		wantOK  bool
	}{
		{"safe under safe", opNOP, proto.ClassSafe, true},
		{"state-changing under safe", opReset, proto.ClassSafe, false},
		{"state-changing under state-changing", opReset, proto.ClassStateChanging, true},
		{"safe under destructive", opFWVer, proto.ClassDestructive, true},
		{"unregistered under destructive", opUnknwn, proto.ClassDestructive, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOpcode(tc.op, tc.ceiling, nil)
			if gotOK := err == nil; gotOK != tc.wantOK {
				t.Fatalf("checkOpcode = %v, want ok=%v", err, tc.wantOK)
			}
		})
	}
}

// Allow is an exact exception: it admits the named opcode above the ceiling and
// nothing else, and it can never admit an unregistered opcode.
func TestCheckOpcodeAllow(t *testing.T) {
	allow := []proto.Opcode{opReset, opUnknwn}
	for _, tc := range []struct {
		name   string
		op     proto.Opcode
		wantOK bool
	}{
		{"allowed state-changing", opReset, true},
		{"other state-changing", 0x20, false},
		{"allowed but unregistered", opUnknwn, false},
		{"safe, not listed", opNOP, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOpcode(tc.op, proto.ClassSafe, allow)
			if gotOK := err == nil; gotOK != tc.wantOK {
				t.Fatalf("checkOpcode = %v, want ok=%v", err, tc.wantOK)
			}
			if err != nil && !errors.Is(err, ErrRefused) {
				t.Fatalf("refusal %v does not wrap ErrRefused", err)
			}
		})
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", o.Timeout, DefaultTimeout)
	}
	if o.Logger == nil {
		t.Error("Logger is nil, want log.Default()")
	}
	if o.Ceiling != proto.ClassSafe {
		t.Errorf("Ceiling = %v, want %v", o.Ceiling, proto.ClassSafe)
	}
}
