package proto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// steadyStateReply is the 0xae reply as captured, byte for byte. It is
// identical in dump.pcapng and restart.pcapng.
const steadyStateReply = "0202310000000100906300000000000000000404"

func TestDecodeMCUState(t *testing.T) {
	raw, err := hex.DecodeString(steadyStateReply)
	if err != nil {
		t.Fatal(err)
	}

	s, err := DecodeMCUState(raw)
	if err != nil {
		t.Fatalf("DecodeMCUState: %v", err)
	}
	if s.Version != 0x02 {
		t.Errorf("Version = 0x%02x, want 0x02", s.Version)
	}
	if s.Status != 0x02 {
		t.Errorf("Status = 0x%02x, want 0x02", s.Status)
	}
	if !s.TLSConnected {
		t.Error("TLSConnected = false; status 0x02 is the steady state, with TLS up")
	}
	if s.POVImageValid {
		t.Error("POVImageValid = true, want false for status 0x02")
	}
	if !bytes.Equal(s.Raw, raw) {
		t.Errorf("Raw = %x, want %x", s.Raw, raw)
	}
}

// TestMCUStatusBytes covers the three status values on record. 0x11 is the only
// one seen on a cold init, where TLS is down.
func TestMCUStatusBytes(t *testing.T) {
	tests := []struct {
		status   byte
		tls, pov bool
	}{
		{0x11, false, true}, // cold init: POV image valid, TLS down
		{0x13, true, true},  // both
		{0x02, true, false}, // steady state: TLS up, no POV image
	}
	for _, tt := range tests {
		payload := make([]byte, mcuStateLen)
		payload[0], payload[1] = 0x02, tt.status

		s, err := DecodeMCUState(payload)
		if err != nil {
			t.Fatalf("status 0x%02x: %v", tt.status, err)
		}
		if s.TLSConnected != tt.tls {
			t.Errorf("status 0x%02x: TLSConnected = %t, want %t", tt.status, s.TLSConnected, tt.tls)
		}
		if s.POVImageValid != tt.pov {
			t.Errorf("status 0x%02x: POVImageValid = %t, want %t", tt.status, s.POVImageValid, tt.pov)
		}
	}
}

func TestDecodeMCUStateRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 19, 21} {
		if _, err := DecodeMCUState(make([]byte, n)); !errors.Is(err, ErrMCUState) {
			t.Errorf("DecodeMCUState(%d bytes) = %v, want ErrMCUState", n, err)
		}
	}
}

// TestEncodeMCUStateRequest checks the request against the bytes actually sent
// in dump.pcapng.
func TestEncodeMCUStateRequest(t *testing.T) {
	got := EncodeMCUStateRequest(0x000052a2)
	want, _ := hex.DecodeString("55a2520000")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeMCUStateRequest = %x, want %x", got, want)
	}
	if err := Opcode(0xae).CheckPayload(len(got)); err != nil {
		t.Errorf("the request violates the registered payload rule: %v", err)
	}
}
