package testfixtures_test

import (
	"bytes"
	"testing"

	"goodix5120/internal/proto"
	"goodix5120/internal/testfixtures"
)

// Breaks caught: mode/marker or timestamp encoding drift, wrong event kind or
// endianness, lost zone flags, threshold wraparound, or the wrong OTP margin.
func TestSharedFDTArms(t *testing.T) {
	for _, s := range testfixtures.Load(t).Prefix("arm.") {
		t.Run(s.Name, func(t *testing.T) {
			op := proto.Opcode(s.Hex(t, "cmd")[0])
			a := proto.FDTArm{Timestamp: uint16(s.Int(t, "timestamp"))}
			copy(a.Thresholds[:], s.Hex(t, "thresholds"))
			got, err := proto.EncodeFDTArm(op, a)
			if err != nil {
				t.Fatal(err)
			}
			want := s.Hex(t, "payload")
			if !bytes.Equal(got, want) {
				t.Fatalf("arm = %x, want %x", got, want)
			}
			decoded, err := proto.DecodeFDTArm(op, want)
			if err != nil || decoded != a {
				t.Fatalf("decode = %+v, %v, want %+v", decoded, err, a)
			}
			if err := op.CheckPayload(len(got)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func sharedFDTEvent(t *testing.T, s testfixtures.Section, key string) proto.FDTEvent {
	t.Helper()
	raw := s.Hex(t, key)
	ev, err := proto.DecodeFDTEvent(proto.Opcode(s.Hex(t, "cmd")[0]), raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != proto.FDTEventKind(s.Int(t, "kind")) || ev.Flags != raw[2] || !bytes.Equal(ev.Header[:], raw[:4]) {
		t.Fatalf("event classification = %+v", ev)
	}
	for i, want := range s.Ints(t, "zones") {
		if ev.Zones[i] != uint16(want) {
			t.Fatalf("zone %d = %d, want %d", i, ev.Zones[i], want)
		}
	}
	return ev
}

func TestSharedFDTEvents(t *testing.T) {
	for _, s := range testfixtures.Load(t).Prefix("event.") {
		t.Run(s.Name, func(t *testing.T) { sharedFDTEvent(t, s, "payload") })
	}
}

func TestSharedFDTThresholds(t *testing.T) {
	for _, s := range testfixtures.Load(t).Prefix("pair.") {
		t.Run(s.Name, func(t *testing.T) {
			ev := sharedFDTEvent(t, s, "event")
			op := proto.Opcode(s.Hex(t, "arm_cmd")[0])
			a := proto.FDTArm{Timestamp: uint16(s.Int(t, "timestamp"))}
			if op == 0x32 {
				a.Thresholds = proto.DownThresholds(ev.Zones)
			} else {
				a.Thresholds = proto.UpThresholds(ev, sharedDelta(t, s.Int(t, "delta")))
			}
			if !bytes.Equal(a.Thresholds[:], s.Hex(t, "thresholds")) {
				t.Fatalf("thresholds = %x, want %x", a.Thresholds, s.Hex(t, "thresholds"))
			}
			got, err := proto.EncodeFDTArm(op, a)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, s.Hex(t, "payload")) {
				t.Fatalf("derived arm = %x, want %x", got, s.Hex(t, "payload"))
			}
		})
	}
}

func sharedDelta(t *testing.T, delta int) byte {
	t.Helper()
	switch delta {
	case 21:
		return proto.FDTDeltaDefault
	case 27:
		return proto.FDTDeltaObserved
	default:
		t.Fatalf("unexpected reference delta %d", delta)
		return 0
	}
}
