package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FDTZones is the number of per-zone readings in a finger-detect frame.
// HYPOTHESIS: every frame observed carries six, and the vendor driver's legend
// names no zone count.
const FDTZones = 6

// fdtHeaderLen is the four-byte header in front of the zone readings.
const fdtHeaderLen = 4

// fdtFrameLen is the length of a finger-detect event payload.
const fdtFrameLen = fdtHeaderLen + 2*FDTZones // 16

// fdtArmMarker is the byte that precedes every per-zone threshold in an arm
// command. HYPOTHESIS: it is a constant marker, not the high byte of a 16-bit
// value — it is 0x80 in all 91 arms in dump.pcapng.
const fdtArmMarker = 0x80

// fdtArmConstant is payload[1] of every arm command observed.
const fdtArmConstant = 0x01

// Arm modes, payload[0] of a finger-detect command. The vendor driver's own
// legend is "1Down2Up3Manual".
const (
	fdtModeDown   = 0x0c
	fdtModeUp     = 0x0e
	fdtModeManual = 0x0d
)

// ErrFDTEvent means a payload is not a well-formed finger-detect frame.
var ErrFDTEvent = errors.New("proto: not a finger-detect frame")

// FDTEventKind names the finger-detect events the EC emits unprompted after an
// arm. The mapping comes from the driver's legend plus the four-byte headers
// counted in dump.pcapng.
type FDTEventKind uint8

const (
	// FDTEventUnknown is a header this code has not seen. It is not an error:
	// the EC has already shown us one header nobody expected.
	FDTEventUnknown FDTEventKind = iota
	FDTEventDown                 // 0x32, header 02 00 <flags> 00 — 21 of 26
	FDTEventUp                   // 0x34, header 00 02 00 00 — 21 of 21
	FDTEventManual               // 0x36, header 00 01 <flags> 00 — 22 of 22
	// FDTEventBaseInvalid is a 0x32 event whose header starts with 0x80, with
	// zeroed readings — 5 of 26 in dump.pcapng. HYPOTHESIS: "base invalid". It
	// arrives about 30 ms after an arm whose thresholds were far from the base,
	// and the driver re-arms at once with fresh ones.
	FDTEventBaseInvalid
)

func (k FDTEventKind) String() string {
	switch k {
	case FDTEventDown:
		return "finger down"
	case FDTEventUp:
		return "finger up"
	case FDTEventManual:
		return "manual"
	case FDTEventBaseInvalid:
		return "base invalid"
	default:
		return "unknown"
	}
}

// FDTEvent is a decoded finger-detect event payload: a four-byte header and six
// 16-bit readings, 16 bytes in all. The length is certain. The meanings below
// are hypotheses.
type FDTEvent struct {
	Kind FDTEventKind

	// Header is the raw first four bytes, kept because only Flags is named.
	Header [fdtHeaderLen]byte

	// Flags is Header[2]. Observed: 0x00, 0x2f, 0x37, 0x3d, 0x3f.
	// HYPOTHESIS (docs/protocol.md): a mask of the zones that triggered.
	Flags byte

	// Zones holds the six readings, little endian. HYPOTHESIS: per-zone
	// capacitance. A base-invalid frame carries zeroes here.
	Zones [FDTZones]uint16
}

// DecodeFDTEvent decodes the payload of a 0x32, 0x34 or 0x36 event message.
// cmd selects the header patterns the payload is matched against.
func DecodeFDTEvent(cmd Opcode, payload []byte) (FDTEvent, error) {
	if len(payload) != fdtFrameLen {
		return FDTEvent{}, fmt.Errorf("%w: payload is %d bytes, want %d", ErrFDTEvent, len(payload), fdtFrameLen)
	}

	var e FDTEvent
	copy(e.Header[:], payload[:fdtHeaderLen])
	e.Flags = payload[2]
	for i := range e.Zones {
		e.Zones[i] = binary.LittleEndian.Uint16(payload[fdtHeaderLen+2*i:])
	}

	switch {
	case cmd == 0x32 && payload[0] == 0x80:
		e.Kind = FDTEventBaseInvalid
	case cmd == 0x32 && payload[0] == 0x02 && payload[1] == 0x00:
		e.Kind = FDTEventDown
	case cmd == 0x34 && payload[0] == 0x00 && payload[1] == 0x02:
		e.Kind = FDTEventUp
	case cmd == 0x36 && payload[0] == 0x00 && payload[1] == 0x01:
		e.Kind = FDTEventManual
	default:
		e.Kind = FDTEventUnknown
	}
	return e, nil
}

// String renders the event for a log line.
func (e FDTEvent) String() string {
	return fmt.Sprintf("FDT %s: header %x, flags 0x%02x, zones %v", e.Kind, e.Header, e.Flags, e.Zones)
}

// FDTArm is the argument of a 0x32, 0x34 or 0x36 arm command.
type FDTArm struct {
	// Thresholds are the six per-zone thresholds, each sent after a 0x80 marker.
	// HYPOTHESIS (docs/protocol.md): derived from the last FDT readings.
	Thresholds [FDTZones]byte

	// Timestamp is the trailing uint16 that only 0x32 carries.
	Timestamp uint16
}

// fdtArmMode maps a command to its mode byte and payload length.
func fdtArmMode(cmd Opcode) (mode byte, length int, ok bool) {
	switch cmd {
	case 0x32:
		return fdtModeDown, 2 + 2*FDTZones + 2, true // 16
	case 0x34:
		return fdtModeUp, 2 + 2*FDTZones, true // 14
	case 0x36:
		return fdtModeManual, 2 + 2*FDTZones, true // 14
	default:
		return 0, 0, false
	}
}

// EncodeFDTArm builds the payload for an arm command: 16 bytes for 0x32, 14 for
// 0x34 and 0x36.
func EncodeFDTArm(cmd Opcode, a FDTArm) ([]byte, error) {
	mode, length, ok := fdtArmMode(cmd)
	if !ok {
		return nil, fmt.Errorf("%w: 0x%02x is not a finger-detect command", ErrFDTEvent, byte(cmd))
	}

	out := make([]byte, length)
	out[0] = mode
	out[1] = fdtArmConstant
	for i, th := range a.Thresholds {
		out[2+2*i] = fdtArmMarker
		out[3+2*i] = th
	}
	if cmd == 0x32 {
		binary.LittleEndian.PutUint16(out[length-2:], a.Timestamp)
	}
	return out, nil
}

// DecodeFDTArm is the inverse of EncodeFDTArm, for reading a capture back.
func DecodeFDTArm(cmd Opcode, payload []byte) (FDTArm, error) {
	mode, length, ok := fdtArmMode(cmd)
	if !ok {
		return FDTArm{}, fmt.Errorf("%w: 0x%02x is not a finger-detect command", ErrFDTEvent, byte(cmd))
	}
	if len(payload) != length {
		return FDTArm{}, fmt.Errorf("%w: payload is %d bytes, want %d", ErrFDTEvent, len(payload), length)
	}
	if payload[0] != mode {
		return FDTArm{}, fmt.Errorf("%w: mode byte is 0x%02x, want 0x%02x", ErrFDTEvent, payload[0], mode)
	}

	var a FDTArm
	for i := range a.Thresholds {
		if payload[2+2*i] != fdtArmMarker {
			return FDTArm{}, fmt.Errorf("%w: zone %d marker is 0x%02x, want 0x%02x",
				ErrFDTEvent, i, payload[2+2*i], fdtArmMarker)
		}
		a.Thresholds[i] = payload[3+2*i]
	}
	if cmd == 0x32 {
		a.Timestamp = binary.LittleEndian.Uint16(payload[length-2:])
	}
	return a, nil
}
