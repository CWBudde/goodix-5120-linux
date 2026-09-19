package proto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestDecodeFDTEventHeaders covers every event header counted in dump.pcapng.
// The counts are from goodix-pcap over that capture.
func TestDecodeFDTEventHeaders(t *testing.T) {
	tests := []struct {
		name   string
		cmd    Opcode
		header string
		want   FDTEventKind
	}{
		{"down, flags 3f", 0x32, "02003f00", FDTEventDown},      // x15
		{"down, flags 2f", 0x32, "02002f00", FDTEventDown},      // x4
		{"down, flags 3d", 0x32, "02003d00", FDTEventDown},      // x1
		{"down, flags 37", 0x32, "02003700", FDTEventDown},      // x1
		{"base invalid", 0x32, "80000000", FDTEventBaseInvalid}, // x5
		{"up", 0x34, "00020000", FDTEventUp},                    // x21
		{"manual, flags 3f", 0x36, "00013f00", FDTEventManual},  // x21
		{"manual, flags 2f", 0x36, "00012f00", FDTEventManual},  // x1
		{"header nobody has seen", 0x32, "7f7f7f7f", FDTEventUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			head, err := hex.DecodeString(tt.header)
			if err != nil {
				t.Fatal(err)
			}
			payload := append(head, make([]byte, 2*FDTZones)...)

			e, err := DecodeFDTEvent(tt.cmd, payload)
			if err != nil {
				t.Fatalf("DecodeFDTEvent: %v", err)
			}
			if e.Kind != tt.want {
				t.Errorf("Kind = %v, want %v", e.Kind, tt.want)
			}
			if e.Flags != payload[2] {
				t.Errorf("Flags = 0x%02x, want 0x%02x", e.Flags, payload[2])
			}
		})
	}
}

// An unrecognised header must not be an error: the EC has already produced one
// header nobody expected, and refusing to decode the next one would lose it.
func TestUnknownFDTHeaderIsNotAnError(t *testing.T) {
	e, err := DecodeFDTEvent(0x32, make([]byte, fdtFrameLen))
	if err != nil {
		t.Fatalf("DecodeFDTEvent: %v", err)
	}
	if e.Kind != FDTEventUnknown {
		t.Errorf("Kind = %v, want FDTEventUnknown", e.Kind)
	}
}

func TestDecodeFDTEventZones(t *testing.T) {
	// Header, then six little-endian uint16 readings.
	payload, err := hex.DecodeString("02003f00" + "1e01" + "3801" + "ff00" + "f700" + "3f01" + "3401")
	if err != nil {
		t.Fatal(err)
	}
	e, err := DecodeFDTEvent(0x32, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := [FDTZones]uint16{0x011e, 0x0138, 0x00ff, 0x00f7, 0x013f, 0x0134}
	if e.Zones != want {
		t.Errorf("Zones = %v, want %v", e.Zones, want)
	}
}

func TestDecodeFDTEventRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 15, 17} {
		if _, err := DecodeFDTEvent(0x32, make([]byte, n)); !errors.Is(err, ErrFDTEvent) {
			t.Errorf("DecodeFDTEvent(%d bytes) = %v, want ErrFDTEvent", n, err)
		}
	}
}

// TestFDTArmRoundTrip checks the encoder against arms actually sent in
// dump.pcapng, then decodes them back.
func TestFDTArmRoundTrip(t *testing.T) {
	tests := []struct {
		cmd  Opcode
		want string
		arm  FDTArm
	}{
		{0x32, "0c0180b880c580ab80b980aa80b9ec5f",
			FDTArm{Thresholds: [FDTZones]byte{0xb8, 0xc5, 0xab, 0xb9, 0xaa, 0xb9}, Timestamp: 0x5fec}},
		{0x34, "0e0180b480aa80808092808a8092",
			FDTArm{Thresholds: [FDTZones]byte{0xb4, 0xaa, 0x80, 0x92, 0x8a, 0x92}}},
		{0x36, "0d0180b480c380a780b780a680b7",
			FDTArm{Thresholds: [FDTZones]byte{0xb4, 0xc3, 0xa7, 0xb7, 0xa6, 0xb7}}},
	}

	for _, tt := range tests {
		want, err := hex.DecodeString(tt.want)
		if err != nil {
			t.Fatal(err)
		}

		got, err := EncodeFDTArm(tt.cmd, tt.arm)
		if err != nil {
			t.Fatalf("EncodeFDTArm(0x%02x): %v", byte(tt.cmd), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("EncodeFDTArm(0x%02x) = %x, want %x", byte(tt.cmd), got, want)
		}
		if err := tt.cmd.CheckPayload(len(got)); err != nil {
			t.Errorf("0x%02x arm violates its registered payload rule: %v", byte(tt.cmd), err)
		}

		back, err := DecodeFDTArm(tt.cmd, want)
		if err != nil {
			t.Fatalf("DecodeFDTArm(0x%02x): %v", byte(tt.cmd), err)
		}
		if back != tt.arm {
			t.Errorf("DecodeFDTArm(0x%02x) = %+v, want %+v", byte(tt.cmd), back, tt.arm)
		}
	}
}

func TestFDTArmRejectsNonFDTOpcode(t *testing.T) {
	if _, err := EncodeFDTArm(0xa8, FDTArm{}); !errors.Is(err, ErrFDTEvent) {
		t.Errorf("EncodeFDTArm(0xa8) = %v, want ErrFDTEvent", err)
	}
	if _, err := DecodeFDTArm(0xa8, nil); !errors.Is(err, ErrFDTEvent) {
		t.Errorf("DecodeFDTArm(0xa8) = %v, want ErrFDTEvent", err)
	}
}

// The 0x80 before each threshold is assumed constant. If a capture ever shows
// otherwise, this is the assumption that was wrong.
func TestFDTArmRejectsBadZoneMarker(t *testing.T) {
	payload, err := hex.DecodeString("0e0181b480aa80808092808a8092")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFDTArm(0x34, payload); !errors.Is(err, ErrFDTEvent) {
		t.Errorf("DecodeFDTArm with a 0x81 marker = %v, want ErrFDTEvent", err)
	}
}
