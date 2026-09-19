package proto

import (
	"errors"
	"slices"
	"testing"
)

func TestPayloadRuleCheck(t *testing.T) {
	tests := []struct {
		name string
		rule PayloadRule
		n    int
		ok   bool
	}{
		{"exactly, match", PayloadExactly(8), 8, true},
		{"exactly, too short", PayloadExactly(8), 0, false},
		{"exactly, too long", PayloadExactly(8), 9, false},
		{"exactly zero, match", PayloadExactly(0), 0, true},
		{"exactly zero, too long", PayloadExactly(0), 1, false},
		{"at least, match", PayloadAtLeast(2), 2, true},
		{"at least, longer", PayloadAtLeast(2), 200, true},
		{"at least, too short", PayloadAtLeast(2), 1, false},
		{"unknown accepts empty", PayloadUnknown(), 0, true},
		{"unknown accepts anything", PayloadUnknown(), 4096, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Check(tt.n)
			if tt.ok && err != nil {
				t.Fatalf("Check(%d) = %v, want nil", tt.n, err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatalf("Check(%d) = nil, want a refusal", tt.n)
				}
				if !errors.Is(err, ErrPayload) {
					t.Fatalf("Check(%d) = %v, want it to wrap ErrPayload", tt.n, err)
				}
			}
		})
	}
}

// TestEmptyPayloadIsRefusedForPSKRead is the regression test for the keyboard
// incident. An 0xe4 with no payload is the frame that wedged the embedded
// controller in Runs 1, 2 and 4 (docs/protocol.md); Run 4 sent it alone, with
// no other command before it, and the internal keyboard still died. The vendor
// driver's 0xe4 carries eight bytes and is answered normally.
//
// If this test ever fails, the code can build that frame again.
func TestEmptyPayloadIsRefusedForPSKRead(t *testing.T) {
	const pskRead Opcode = 0xe4

	if err := pskRead.CheckPayload(0); !errors.Is(err, ErrPayload) {
		t.Fatalf("CheckPayload(0) = %v, want a refusal wrapping ErrPayload", err)
	}
	if err := pskRead.CheckPayload(8); err != nil {
		t.Fatalf("CheckPayload(8) = %v, want nil — that is the vendor's payload", err)
	}
}

// TestEmptyPayloadIsRefusedForReadOTP covers the same shape for read_otp. Run 1
// sent it empty and got neither an ACK nor data; the vendor sends `00 00` and
// gets an ACK plus 64 bytes.
func TestEmptyPayloadIsRefusedForReadOTP(t *testing.T) {
	const readOTP Opcode = 0xa6

	if err := readOTP.CheckPayload(0); !errors.Is(err, ErrPayload) {
		t.Fatalf("CheckPayload(0) = %v, want a refusal wrapping ErrPayload", err)
	}
	if err := readOTP.CheckPayload(2); err != nil {
		t.Fatalf("CheckPayload(2) = %v, want nil", err)
	}
}

func TestCheckPayloadRefusesUnregisteredOpcode(t *testing.T) {
	const unknown Opcode = 0x7b
	if _, ok := unknown.Class(); ok {
		t.Fatalf("0x%02x is registered; pick another opcode for this test", byte(unknown))
	}
	if err := unknown.CheckPayload(4); !errors.Is(err, ErrPayload) {
		t.Fatalf("CheckPayload on an unregistered opcode = %v, want a refusal", err)
	}
}

func TestEveryRegisteredOpcodeHasARule(t *testing.T) {
	for _, op := range Registered() {
		if _, ok := op.PayloadRule(); !ok {
			t.Errorf("opcode 0x%02x (%s) has no payload rule", byte(op), op.Name())
		}
	}
}

// TestPayloadRulesAreEvidenceBased pins the opcodes allowed to carry
// PayloadUnknown(). Every other opcode's rule comes from a payload the vendor
// driver was observed to send, so this list may only shrink — and growing it
// has to be a deliberate edit reviewed alongside the reason.
func TestPayloadRulesAreEvidenceBased(t *testing.T) {
	want := []Opcode{
		0x00, // nop — the vendor never sends it to an ITE EC
		0xf4, // check_firmware — the vendor skips the firmware path entirely
	}
	if destructiveEnabled {
		// write_firmware and preset_psk_write: never sent, never to be sent.
		want = append(want, 0xe0, 0xf0)
	}
	slices.Sort(want)

	var got []Opcode
	for _, op := range Registered() {
		rule, ok := op.PayloadRule()
		if ok && !rule.Known() {
			got = append(got, op)
		}
	}

	if !slices.Equal(got, want) {
		t.Errorf("opcodes without a payload rule = %#x, want %#x", got, want)
	}
}
