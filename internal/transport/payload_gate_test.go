package transport

import (
	"context"
	"errors"
	"testing"

	"goodix5120/internal/proto"
)

const opPSKRead proto.Opcode = 0xe4 // state-changing; wedges the EC with an empty payload

// vendorPSKReadPayload is the 8-byte argument the Windows driver sends with
// every 0xe4: data_type 0xbb020003 little endian, then a uint32 length of 0.
var vendorPSKReadPayload = []byte{0x03, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00}

// TestSendRefusesTheFrameThatWedgedTheEC is the regression test for the
// keyboard incident, and the reason the payload gate exists.
//
// `a0 04 00 a4 e4 01 00 c5` — 0xe4 with no payload — was sent in Runs 1, 2 and
// 4 (docs/protocol.md). Every time, the EC acknowledged it and then stopped
// serving the i8042, killing the laptop's internal keyboard until a cold power
// cycle. Run 4 sent it alone, after nothing but an attach, so no other command
// is needed to trigger it.
//
// The ceiling is raised and 0xe4 is explicitly allowed here, so neither the
// class gate nor the allowlist can mask the result: what refuses the frame must
// be the payload rule, and nothing else. If this test fails, some code path can
// build that frame again.
func TestSendRefusesTheFrameThatWedgedTheEC(t *testing.T) {
	var written int
	s := &sender{
		opts: Options{
			Ceiling: proto.ClassStateChanging,
			Allow:   []proto.Opcode{opPSKRead},
		}.withDefaults(),
		write: func(context.Context, proto.Opcode, []byte, []byte) error {
			written++
			return nil
		},
	}

	err := s.Send(opPSKRead, nil)
	if err == nil {
		t.Fatal("Send(0xe4, nil) succeeded; that frame killed the keyboard three times")
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("Send(0xe4, nil) = %v, want it to wrap ErrRefused", err)
	}
	if !errors.Is(err, proto.ErrPayload) {
		t.Errorf("Send(0xe4, nil) = %v, want it to wrap proto.ErrPayload — "+
			"the payload rule must be what refused it, not the ceiling", err)
	}
	if written != 0 {
		t.Errorf("the frame reached the writer %d time(s); the gate must refuse before any byte is written", written)
	}

	// The vendor's own frame, by contrast, must go out: PLAN.md Phase 4 plans
	// exactly this command live, and refusing it would make the gate useless.
	if err := s.Send(opPSKRead, vendorPSKReadPayload); err != nil {
		t.Fatalf("Send(0xe4, vendor payload) = %v, want nil", err)
	}
	if written != 1 {
		t.Errorf("writer saw %d frames, want 1", written)
	}
}

// TestSendRefusesPayloadlessCommandsThatNeedOne covers the same shape for the
// other commands the vendor never sends empty. read_otp is the near miss: Run 1
// sent `a6` empty and got neither an ACK nor data, which fits the 0xe4 pattern.
func TestSendRefusesPayloadlessCommandsThatNeedOne(t *testing.T) {
	s := &sender{
		opts: Options{Ceiling: proto.ClassStateChanging}.withDefaults(),
		write: func(context.Context, proto.Opcode, []byte, []byte) error {
			t.Error("a refused frame reached the writer")
			return nil
		},
	}

	for _, op := range []proto.Opcode{0xa6, 0xa8, 0xae, 0x82, 0xa2, 0x70, 0xd0} {
		if err := s.Send(op, nil); !errors.Is(err, proto.ErrPayload) {
			t.Errorf("Send(0x%02x, nil) = %v, want a refusal wrapping proto.ErrPayload", byte(op), err)
		}
	}
}

// TestClassIsCheckedBeforePayload keeps refusals naming the most serious
// reason. A destructive or over-ceiling opcode is refused for that, not for the
// shape of its arguments.
func TestClassIsCheckedBeforePayload(t *testing.T) {
	err := check(opPSKRead, nil, proto.ClassSafe, nil)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("check = %v, want ErrRefused", err)
	}
	if errors.Is(err, proto.ErrPayload) {
		t.Errorf("check = %v, want the ceiling to be the stated reason, not the payload", err)
	}
}

// TestNopRemainsPayloadAgnostic pins the one opcode tests rely on being
// sendable with any payload. The vendor driver never sends nop to an ITE EC, so
// there is nothing to copy and no rule to enforce.
func TestNopRemainsPayloadAgnostic(t *testing.T) {
	for _, n := range []int{0, 2, 4} {
		if err := opNOP.CheckPayload(n); err != nil {
			t.Errorf("nop.CheckPayload(%d) = %v, want nil", n, err)
		}
	}
}
