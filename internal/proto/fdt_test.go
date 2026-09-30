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

// fdtPair is an event from dump.pcapng and the arm the vendor driver sent next.
type fdtPair struct {
	name  string
	cmd   Opcode // the event's opcode
	event string
	arm   Opcode
	want  string // the arm payload the driver sent
}

// fdtCapturePairs are consecutive event/arm pairs read out of dump.pcapng with
// `goodix-pcap -show 32` (and 34), frame numbers in the names. They include
// every case the rules have to get right: a plain lift, a lift that was not
// quite a lift (the base-invalid reply after it), and down events where the
// finger missed a zone.
var fdtCapturePairs = []fdtPair{
	{"up 26 -> down arm 27", 0x34, "0002000070018b015701730154017201",
		0x32, "0c0180b880c580ab80b980aa80b9ec5f"},
	{"up 60 -> down arm 61", 0x34, "000200005c01830151016f0153017101",
		0x32, "0c0180ae80c180a880b780a980b8136a"},
	{"up 128, finger not quite lifted -> down arm 129", 0x34, "0002000051018601fb006a012b016a01",
		0x32, "0c0180a880c3807d80b5809580b5cf7f"},
	{"base invalid 131 -> down arm 132", 0x32, "8000000071018c015601720154017201",
		0x32, "0c0180b880c680ab80b980aa80b9fd7f"},
	{"down 4, all zones -> up arm 8", 0x32, "02003f0032011f01cb00ee00de00ee00",
		0x34, "0e0180b480aa80808092808a8092"},
	{"down 29, zone 4 uncovered -> up arm 33", 0x32, "02002f00d1000d01b50005013f011c01",
		0x34, "0e01808380a18075809d801980a9"},
	{"down 134, zone 1 uncovered -> up arm 138", 0x32, "02003d00ea008301bb003701c200fd00",
		0x34, "0e0180908019807880b6807c8099"},
}

// TestThresholdRulesReproduceTheVendor derives each arm from the event before
// it and compares with what the vendor driver actually sent. The timestamp in
// a down arm is not derived, so it is copied from the capture.
func TestThresholdRulesReproduceTheVendor(t *testing.T) {
	for _, p := range fdtCapturePairs {
		t.Run(p.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(p.event)
			want, _ := hex.DecodeString(p.want)
			ev, err := DecodeFDTEvent(p.cmd, raw)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := DecodeFDTArm(p.arm, want)
			if err != nil {
				t.Fatal(err)
			}

			var arm FDTArm
			switch p.arm {
			case 0x32:
				arm.Thresholds = DownThresholds(ev.Zones)
				arm.Timestamp = sent.Timestamp
			case 0x34:
				arm.Thresholds = UpThresholds(ev, FDTDeltaObserved)
			}
			got, err := EncodeFDTArm(p.arm, arm)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("derived %x, the driver sent %x", got, want)
			}
		})
	}
}

// A reading too large for a byte must saturate rather than wrap: a wrapped
// threshold would be tiny, and a tiny down threshold never fires.
func TestThresholdsSaturate(t *testing.T) {
	down := DownThresholds([FDTZones]uint16{0xffff, 0x200, 0x1fe, 0, 1, 2})
	if want := [FDTZones]byte{0xff, 0xff, 0xff, 0, 0, 1}; down != want {
		t.Errorf("DownThresholds = %x, want %x", down, want)
	}
	up := UpThresholds(FDTEvent{Flags: 0x3f, Zones: [FDTZones]uint16{0x1f0, 0x1c8, 0, 0, 0, 0}}, FDTDeltaObserved)
	if up[0] != 0xff || up[1] != 0xff || up[2] != FDTDeltaObserved {
		t.Errorf("UpThresholds = %x, want ff ff %02x …", up, FDTDeltaObserved)
	}
}
