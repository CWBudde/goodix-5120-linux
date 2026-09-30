package proto

import (
	"encoding/hex"
	"errors"
	"testing"
)

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

func TestDecodeFDTEventRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 15, 17} {
		if _, err := DecodeFDTEvent(0x32, make([]byte, n)); !errors.Is(err, ErrFDTEvent) {
			t.Errorf("DecodeFDTEvent(%d bytes) = %v, want ErrFDTEvent", n, err)
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
