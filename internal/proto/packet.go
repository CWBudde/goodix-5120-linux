package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Pack flag values.
const (
	// FlagMessage marks a pack whose payload is a protocol message.
	FlagMessage byte = 0xa0
	// FlagTLSData and FlagTLSAlt mark packs whose payload is TLS record data.
	FlagTLSData byte = 0xb0
	FlagTLSAlt  byte = 0xb2
)

// noChecksumMarker is the literal byte the device accepts in place of a
// computed message checksum when checksums are disabled.
const noChecksumMarker byte = 0x88

// packHeaderLen is the size of the pack header: flags, length, checksum.
const packHeaderLen = 4

// messageHeaderLen is the size of the message header: command and length.
const messageHeaderLen = 3

// Framing errors. Callers should match with errors.Is.
var (
	// ErrShortBuffer means the buffer is too small to even hold a header.
	ErrShortBuffer = errors.New("proto: buffer too short")
	// ErrLength means the declared length is inconsistent with the buffer.
	ErrLength = errors.New("proto: inconsistent length")
	// ErrChecksum means the frame's checksum did not verify.
	ErrChecksum = errors.New("proto: bad checksum")
)

// EncodeMessage builds the inner message layer:
//
//	[cmd:1][length:2 LE][payload:N][checksum:1]
//
// The length field carries len(payload)+1, the +1 accounting for the trailing
// checksum byte. The checksum is (0xaa - sum(frame[:3+len(payload)])) & 0xff.
// When noChecksum is true the literal marker 0x88 is emitted instead.
func EncodeMessage(cmd Opcode, payload []byte, noChecksum bool) []byte {
	out := make([]byte, messageHeaderLen+len(payload)+1)
	out[0] = byte(cmd)
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)+1))
	copy(out[messageHeaderLen:], payload)

	if noChecksum {
		out[len(out)-1] = noChecksumMarker
	} else {
		out[len(out)-1] = messageChecksum(out[:len(out)-1])
	}
	return out
}

// EncodePack builds the outer pack layer:
//
//	[flags:1][length:2 LE][checksum:1][payload:N]
//
// The checksum covers the flags byte and the two length bytes only.
func EncodePack(flags byte, payload []byte) []byte {
	out := make([]byte, packHeaderLen+len(payload))
	out[0] = flags
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(payload)))
	out[3] = packChecksum(out[:3])
	copy(out[packHeaderLen:], payload)
	return out
}

// Encode is the common case: a checksummed message wrapped in a message-protocol
// pack, ready to write to the device.
func Encode(cmd Opcode, payload []byte) []byte {
	return EncodePack(FlagMessage, EncodeMessage(cmd, payload, false))
}

// DecodePack parses the outer pack layer and returns the flags byte and the
// payload. The payload is a copy, so the caller may retain it after the input
// buffer is reused. Bytes past the declared length are ignored: USB transfers
// arrive padded to the endpoint packet size.
func DecodePack(b []byte) (flags byte, payload []byte, err error) {
	if len(b) < packHeaderLen {
		return 0, nil, fmt.Errorf("%w: pack needs %d bytes, got %d", ErrShortBuffer, packHeaderLen, len(b))
	}
	if want := packChecksum(b[:3]); b[3] != want {
		return 0, nil, fmt.Errorf("%w: pack checksum %#02x, want %#02x", ErrChecksum, b[3], want)
	}

	n := int(binary.LittleEndian.Uint16(b[1:3]))
	if len(b) < packHeaderLen+n {
		return 0, nil, fmt.Errorf("%w: pack declares %d payload bytes, buffer holds %d", ErrLength, n, len(b)-packHeaderLen)
	}

	payload = make([]byte, n)
	copy(payload, b[packHeaderLen:packHeaderLen+n])
	return b[0], payload, nil
}

// DecodeMessage parses the inner message layer and returns the command byte and
// the payload. The payload is a copy. The buffer must contain exactly one
// message: trailing bytes are an error, because a message never carries padding
// of its own. The trailing byte verifies either as a computed checksum or as the
// no-checksum marker 0x88.
func DecodeMessage(b []byte) (cmd Opcode, payload []byte, err error) {
	if len(b) < messageHeaderLen+1 {
		return 0, nil, fmt.Errorf("%w: message needs %d bytes, got %d", ErrShortBuffer, messageHeaderLen+1, len(b))
	}

	length := int(binary.LittleEndian.Uint16(b[1:3]))
	if length < 1 {
		return 0, nil, fmt.Errorf("%w: message length field is %d, want at least 1", ErrLength, length)
	}

	total := messageHeaderLen + length // header + payload + checksum byte
	if len(b) != total {
		return 0, nil, fmt.Errorf("%w: message declares %d bytes, buffer holds %d", ErrLength, total, len(b))
	}

	if got := b[total-1]; got != noChecksumMarker {
		if want := messageChecksum(b[:total-1]); got != want {
			return 0, nil, fmt.Errorf("%w: message checksum %#02x, want %#02x", ErrChecksum, got, want)
		}
	}

	payload = make([]byte, length-1)
	copy(payload, b[messageHeaderLen:total-1])
	return Opcode(b[0]), payload, nil
}

// IsAck reports whether received is the acknowledgement of sent. The device
// acknowledges a command by echoing its command byte with bit 0 set before it
// sends the actual response.
func IsAck(sent, received Opcode) bool {
	return byte(received) == byte(sent)|0x01 && received != sent
}

// packChecksum sums the flags and length bytes.
func packChecksum(header []byte) byte {
	var sum byte
	for _, c := range header {
		sum += c
	}
	return sum
}

// messageChecksum computes 0xaa minus the sum of every byte preceding the
// checksum, truncated to eight bits.
func messageChecksum(b []byte) byte {
	var sum byte
	for _, c := range b {
		sum += c
	}
	return 0xaa - sum
}
