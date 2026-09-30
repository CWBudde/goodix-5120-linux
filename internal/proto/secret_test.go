package proto

import "testing"

func TestSecretPack(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want bool
	}{
		{"0xe4 reply", Encode(0xe4, []byte{0x00, 0x03, 0x00, 0x01}), true},
		{"0xa6 reply", Encode(0xa6, make([]byte, 65)), true},
		// A reply cut short is still withheld: only the flags and the command
		// byte are read.
		{"truncated 0xa6", Encode(0xa6, make([]byte, 65))[:9], true},
		{"0xa8 reply", Encode(0xa8, []byte("GF_ITE_EC_20063\x00")), false},
		// The ACK for 0xe4 names it in its payload, not as its command, and
		// carries nothing secret.
		{"ACK for 0xe4", Encode(AckCmd, []byte{0xe4, 0x01}), false},
		{"TLS data", EncodePack(FlagTLSData, []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0xe4}), false},
		{"header only", []byte{FlagMessage, 0x00, 0x00, 0x00}, false},
	}
	for _, c := range cases {
		if _, _, got := SecretPack(c.raw); got != c.want {
			t.Errorf("%s: SecretPack = %v, want %v", c.name, got, c.want)
		}
	}
}

// The deny list is keyed by opcode, so it must name opcodes that exist, and it
// must name the two whose replies PLAN.md says never to publish.
func TestSecretOpcodesAreRegistered(t *testing.T) {
	for op := range secretReplies {
		if _, ok := op.Class(); !ok {
			t.Errorf("deny list names unregistered opcode 0x%02x", byte(op))
		}
	}
	for _, op := range []Opcode{0xe4, 0xa6} {
		if _, ok := SecretReply(op); !ok {
			t.Errorf("0x%02x (%s) is not on the deny list", byte(op), op.Name())
		}
	}
}
