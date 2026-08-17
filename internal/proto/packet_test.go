package proto

import (
	"bytes"
	"errors"
	"testing"
)

// --- Hand-computed golden frames -------------------------------------------
//
// nop (0x00), empty payload:
//
//	message: cmd=0x00, lengthField = len(payload)+1 = 1 -> 0x01 0x00
//	         checksum = (0xaa - (0x00+0x01+0x00)) & 0xff = 0xa9
//	         => 00 01 00 a9
//	pack:    flags=0xa0, length = 4 -> 0x04 0x00
//	         checksum = (0xa0+0x04+0x00) & 0xff = 0xa4
//	         => a0 04 00 a4 00 01 00 a9
//
// firmware_version (0xa8), empty payload:
//
//	message: checksum = (0xaa - (0xa8+0x01+0x00)) & 0xff = 0x01
//	         => a8 01 00 01
//	pack:    => a0 04 00 a4 a8 01 00 01

func TestEncodeMessageGolden(t *testing.T) {
	tests := []struct {
		name       string
		cmd        Opcode
		payload    []byte
		noChecksum bool
		want       []byte
	}{
		{
			name: "nop empty payload",
			cmd:  0x00,
			want: []byte{0x00, 0x01, 0x00, 0xa9},
		},
		{
			name: "firmware_version empty payload",
			cmd:  0xa8,
			want: []byte{0xa8, 0x01, 0x00, 0x01},
		},
		{
			name:    "one byte payload",
			cmd:     0x96,
			payload: []byte{0x01},
			// 0x96 02 00 01 -> sum = 0x96+0x02+0x00+0x01 = 0x99
			// checksum = 0xaa - 0x99 = 0x11
			want: []byte{0x96, 0x02, 0x00, 0x01, 0x11},
		},
		{
			name:    "checksum wraps past 0xff",
			cmd:     0xa8,
			payload: []byte{0xff, 0xff},
			// a8 03 00 ff ff -> sum = 0x2a9; (0xaa-0x2a9)&0xff = 0x01
			want: []byte{0xa8, 0x03, 0x00, 0xff, 0xff, 0x01},
		},
		{
			name:       "no checksum mode uses literal 0x88",
			cmd:        0xa8,
			payload:    []byte{0x01, 0x02},
			noChecksum: true,
			want:       []byte{0xa8, 0x03, 0x00, 0x01, 0x02, 0x88},
		},
		{
			name:       "no checksum mode empty payload",
			cmd:        0x00,
			noChecksum: true,
			want:       []byte{0x00, 0x01, 0x00, 0x88},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeMessage(tt.cmd, tt.payload, tt.noChecksum)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("EncodeMessage() = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestEncodePackGolden(t *testing.T) {
	tests := []struct {
		name    string
		flags   byte
		payload []byte
		want    []byte
	}{
		{
			name:  "empty payload",
			flags: 0xa0,
			// checksum = (0xa0+0x00+0x00) & 0xff = 0xa0
			want: []byte{0xa0, 0x00, 0x00, 0xa0},
		},
		{
			name:    "message protocol nop",
			flags:   0xa0,
			payload: []byte{0x00, 0x01, 0x00, 0xa9},
			want:    []byte{0xa0, 0x04, 0x00, 0xa4, 0x00, 0x01, 0x00, 0xa9},
		},
		{
			name:    "tls flags",
			flags:   0xb0,
			payload: []byte{0xde, 0xad, 0xbe, 0xef},
			// checksum = (0xb0+0x04+0x00) & 0xff = 0xb4
			want: []byte{0xb0, 0x04, 0x00, 0xb4, 0xde, 0xad, 0xbe, 0xef},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodePack(tt.flags, tt.payload)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("EncodePack() = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestEncodePackChecksumWraps(t *testing.T) {
	// 192 bytes of payload: length bytes are 0xc0 0x00.
	// checksum = (0xb0 + 0xc0 + 0x00) & 0xff = 0x170 & 0xff = 0x70
	got := EncodePack(0xb0, make([]byte, 192))
	want := []byte{0xb0, 0xc0, 0x00, 0x70}
	if !bytes.Equal(got[:4], want) {
		t.Fatalf("header = % x, want % x", got[:4], want)
	}
	if len(got) != 4+192 {
		t.Fatalf("len = %d, want %d", len(got), 4+192)
	}
}

func TestEncodePackLittleEndianLength(t *testing.T) {
	// 300 bytes -> 0x012c -> 0x2c 0x01 little endian.
	got := EncodePack(0xa0, make([]byte, 300))
	if got[1] != 0x2c || got[2] != 0x01 {
		t.Fatalf("length bytes = %#x %#x, want 0x2c 0x01", got[1], got[2])
	}
	// checksum = (0xa0+0x2c+0x01) & 0xff = 0xcd
	if got[3] != 0xcd {
		t.Fatalf("checksum = %#x, want 0xcd", got[3])
	}
}

func TestEncodeGolden(t *testing.T) {
	tests := []struct {
		name    string
		cmd     Opcode
		payload []byte
		want    []byte
	}{
		{
			name: "nop",
			cmd:  0x00,
			want: []byte{0xa0, 0x04, 0x00, 0xa4, 0x00, 0x01, 0x00, 0xa9},
		},
		{
			name: "firmware_version",
			cmd:  0xa8,
			want: []byte{0xa0, 0x04, 0x00, 0xa4, 0xa8, 0x01, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.cmd, tt.payload)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Encode() = % x, want % x", got, tt.want)
			}
		})
	}
}

func TestRoundTripMessage(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 15, 16, 64, 255, 256, 1024}
	for _, noChecksum := range []bool{false, true} {
		for _, n := range sizes {
			payload := make([]byte, n)
			for i := range payload {
				payload[i] = byte(i * 7)
			}
			frame := EncodeMessage(0xa8, payload, noChecksum)
			cmd, got, err := DecodeMessage(frame)
			if err != nil {
				t.Fatalf("n=%d noChecksum=%v: DecodeMessage() error: %v", n, noChecksum, err)
			}
			if cmd != 0xa8 {
				t.Fatalf("n=%d: cmd = %#x, want 0xa8", n, byte(cmd))
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("n=%d: payload mismatch", n)
			}
		}
	}
}

func TestRoundTripPack(t *testing.T) {
	sizes := []int{0, 1, 7, 64, 255, 256, 4096}
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(255 - i)
		}
		frame := EncodePack(0xb2, payload)
		flags, got, err := DecodePack(frame)
		if err != nil {
			t.Fatalf("n=%d: DecodePack() error: %v", n, err)
		}
		if flags != 0xb2 {
			t.Fatalf("n=%d: flags = %#x, want 0xb2", n, flags)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("n=%d: payload mismatch", n)
		}
	}
}

func TestRoundTripNested(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	frame := Encode(0x20, payload)

	flags, inner, err := DecodePack(frame)
	if err != nil {
		t.Fatalf("DecodePack() error: %v", err)
	}
	if flags != 0xa0 {
		t.Fatalf("flags = %#x, want 0xa0", flags)
	}
	cmd, got, err := DecodeMessage(inner)
	if err != nil {
		t.Fatalf("DecodeMessage() error: %v", err)
	}
	if cmd != 0x20 {
		t.Fatalf("cmd = %#x, want 0x20", byte(cmd))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = % x, want % x", got, payload)
	}
}

func TestEncodeDoesNotAliasPayload(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	frame := EncodeMessage(0xa8, payload, false)
	payload[0] = 0xff
	if frame[3] != 0x01 {
		t.Fatalf("frame aliases the caller's payload slice")
	}
}

func TestDecodePackErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{name: "nil", in: nil, want: ErrShortBuffer},
		{name: "truncated header", in: []byte{0xa0, 0x04, 0x00}, want: ErrShortBuffer},
		{
			name: "bad checksum",
			in:   []byte{0xa0, 0x04, 0x00, 0xa5, 0x00, 0x01, 0x00, 0xa9},
			want: ErrChecksum,
		},
		{
			name: "length longer than buffer",
			in:   []byte{0xa0, 0x08, 0x00, 0xa8, 0x00, 0x01, 0x00, 0xa9},
			want: ErrLength,
		},
		{
			name: "truncated payload",
			in:   []byte{0xa0, 0x04, 0x00, 0xa4, 0x00, 0x01},
			want: ErrLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodePack(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("DecodePack() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecodePackIgnoresTrailingPadding(t *testing.T) {
	// USB transfers arrive padded to the endpoint packet size; the declared
	// length wins and trailing bytes are dropped.
	in := []byte{0xa0, 0x04, 0x00, 0xa4, 0x00, 0x01, 0x00, 0xa9, 0x00, 0x00, 0x00}
	flags, payload, err := DecodePack(in)
	if err != nil {
		t.Fatalf("DecodePack() error: %v", err)
	}
	if flags != 0xa0 {
		t.Fatalf("flags = %#x, want 0xa0", flags)
	}
	if !bytes.Equal(payload, []byte{0x00, 0x01, 0x00, 0xa9}) {
		t.Fatalf("payload = % x", payload)
	}
}

func TestDecodeMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{name: "nil", in: nil, want: ErrShortBuffer},
		{name: "truncated header", in: []byte{0xa8, 0x01}, want: ErrShortBuffer},
		{name: "zero length field", in: []byte{0xa8, 0x00, 0x00, 0x02}, want: ErrLength},
		{
			name: "bad checksum",
			in:   []byte{0xa8, 0x01, 0x00, 0x02},
			want: ErrChecksum,
		},
		{
			name: "length field longer than buffer",
			in:   []byte{0xa8, 0x05, 0x00, 0x01, 0x02},
			want: ErrLength,
		},
		{
			name: "length field shorter than buffer",
			in:   []byte{0xa8, 0x01, 0x00, 0x01, 0x00, 0x00},
			want: ErrLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodeMessage(tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("DecodeMessage() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDecodeMessageAcceptsNoChecksumMarker(t *testing.T) {
	in := []byte{0xa8, 0x03, 0x00, 0x01, 0x02, 0x88}
	cmd, payload, err := DecodeMessage(in)
	if err != nil {
		t.Fatalf("DecodeMessage() error: %v", err)
	}
	if cmd != 0xa8 {
		t.Fatalf("cmd = %#x, want 0xa8", byte(cmd))
	}
	if !bytes.Equal(payload, []byte{0x01, 0x02}) {
		t.Fatalf("payload = % x", payload)
	}
}

func TestIsAck(t *testing.T) {
	tests := []struct {
		name     string
		sent     Opcode
		received Opcode
		want     bool
	}{
		{name: "nop ack", sent: 0x00, received: 0x01, want: true},
		{name: "firmware_version ack", sent: 0xa8, received: 0xa9, want: true},
		{name: "reset ack", sent: 0xa2, received: 0xa3, want: true},
		{name: "mcu_get_image ack", sent: 0x20, received: 0x21, want: true},
		{name: "echo of sent command is not an ack", sent: 0xa8, received: 0xa8, want: false},
		{name: "unrelated opcode", sent: 0xa8, received: 0xb0, want: false},
		{name: "ack of a different command", sent: 0xa8, received: 0x21, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAck(tt.sent, tt.received); got != tt.want {
				t.Fatalf("IsAck(%#x, %#x) = %v, want %v", byte(tt.sent), byte(tt.received), got, tt.want)
			}
		})
	}
}
