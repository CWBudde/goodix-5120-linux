package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// mcuStateLen is the length of a get_mcu_state (0xae) reply.
const mcuStateLen = 20

// ErrMCUState means a payload is not a well-formed MCU state reply.
var ErrMCUState = errors.New("proto: not an MCU state reply")

// MCUState is the decoded reply to get_mcu_state (0xae).
//
// The reply arrives with NO acknowledgement: it is the one command in the
// vendor init whose data comes back on its own.
//
// Only one bit of it is understood. The rest is kept as raw bytes rather than
// given invented names.
type MCUState struct {
	// Version is payload[0]. The only value ever seen, in both USB captures and
	// all eight vendor inits, is 0x02.
	Version byte

	// Status is payload[1]. Observed: 0x11 on a cold init, 0x13, and 0x02 in
	// steady state (both captures).
	Status byte

	// TLSConnected is Status bit 1 (0x02). This one is solid: the vendor driver
	// logs isTlsConnected=1 for exactly 0x13 and 0x02, and 0 for 0x11.
	TLSConnected bool

	// POVImageValid is Status bit 0 (0x01). HYPOTHESIS, and a weak one. Bit 0
	// and bit 4 (0x10) have only ever been seen set together (0x11, 0x13) or
	// clear together (0x02), so the evidence cannot say which of them carries
	// the meaning, or whether they are one two-bit field. Do not rely on it.
	POVImageValid bool

	// Raw is the full 20-byte payload. Bytes 2..19 have no interpretation yet;
	// the steady-state value, identical in dump.pcapng and restart.pcapng, is
	// 02 02 31 00 00 00 01 00 90 63 00 00 00 00 00 00 00 00 04 04.
	Raw []byte
}

// Status bits. Only statusTLSConnected is confirmed.
const (
	statusPOVImageValid = 1 << 0
	statusTLSConnected  = 1 << 1
)

// DecodeMCUState decodes the message payload of a get_mcu_state reply.
func DecodeMCUState(payload []byte) (MCUState, error) {
	if len(payload) != mcuStateLen {
		return MCUState{}, fmt.Errorf("%w: payload is %d bytes, want %d", ErrMCUState, len(payload), mcuStateLen)
	}
	return MCUState{
		Version:       payload[0],
		Status:        payload[1],
		TLSConnected:  payload[1]&statusTLSConnected != 0,
		POVImageValid: payload[1]&statusPOVImageValid != 0,
		Raw:           slices.Clone(payload),
	}, nil
}

// String renders the state for a log line. Status is printed in hex as well as
// decoded, so a value nobody has seen before is visible rather than silently
// reduced to two booleans.
func (s MCUState) String() string {
	return fmt.Sprintf("MCU state: version 0x%02x, status 0x%02x (TLS connected=%t, POV image valid=%t, unconfirmed)",
		s.Version, s.Status, s.TLSConnected, s.POVImageValid)
}

// EncodeMCUStateRequest builds the get_mcu_state payload the vendor driver
// sends: the literal 0x55 followed by a host timestamp in milliseconds, little
// endian.
//
// The timestamp is the low 32 bits of a free-running host counter. The EC has
// never been observed to react to its value — the two captures carry different
// ones and get byte-identical replies — so a caller may pass anything.
func EncodeMCUStateRequest(timestampMS uint32) []byte {
	out := make([]byte, 5)
	out[0] = 0x55
	binary.LittleEndian.PutUint32(out[1:], timestampMS)
	return out
}
