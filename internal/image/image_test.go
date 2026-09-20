package image

import (
	"bytes"
	"errors"
	"testing"
)

func TestWritePGM(t *testing.T) {
	img := Gray8{
		Width:  3,
		Height: 2,
		Pix:    []byte{0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff},
	}
	var buf bytes.Buffer
	if err := WritePGM(&buf, img); err != nil {
		t.Fatalf("WritePGM: %v", err)
	}
	want := append([]byte("P5\n3 2\n255\n"), img.Pix...)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("PGM mismatch\n got: %q\nwant: %q", buf.Bytes(), want)
	}
}

func TestWritePGMRejectsInvalid(t *testing.T) {
	var buf bytes.Buffer
	err := WritePGM(&buf, Gray8{Width: 2, Height: 2, Pix: []byte{1, 2, 3}})
	if err == nil {
		t.Fatal("expected error for mismatched pixel buffer")
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing should have been written, got %d bytes", buf.Len())
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		img     Gray8
		wantErr bool
	}{
		{"ok", Gray8{2, 2, make([]byte, 4)}, false},
		{"short pix", Gray8{2, 2, make([]byte, 3)}, true},
		{"long pix", Gray8{2, 2, make([]byte, 5)}, true},
		{"zero width", Gray8{0, 2, nil}, true},
		{"zero height", Gray8{2, 0, nil}, true},
		{"negative width", Gray8{-1, 2, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.img.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Hand-computed from the upstream layout:
//
//	b = 0x12 0x34 0x56 0x78 0x9a 0xbc
//	s0 = (0x12 & 0x0f) << 8 | 0x34 = 0x234
//	s1 = 0x78 << 4 | 0x12 >> 4     = 0x781
//	s2 = (0xbc & 0x0f) << 8 | 0x56 = 0xc56
//	s3 = 0x9a << 4 | 0xbc >> 4     = 0x9ab
func TestDecode12BitRaw(t *testing.T) {
	raw := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	got, err := Decode12BitRaw(raw, 4, 1)
	if err != nil {
		t.Fatalf("Decode12BitRaw: %v", err)
	}
	want := []uint16{0x234, 0x781, 0xc56, 0x9ab}
	if len(got) != len(want) {
		t.Fatalf("got %d samples, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sample %d = 0x%03x, want 0x%03x", i, got[i], want[i])
		}
		if got[i] > 0x0fff {
			t.Errorf("sample %d = 0x%04x exceeds 12 bits", i, got[i])
		}
	}
}

func TestDecode12BitPacked(t *testing.T) {
	// Two groups -> 8 samples -> a 4x2 frame.
	raw := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	img, err := Decode12BitPacked(raw, 4, 2)
	if err != nil {
		t.Fatalf("Decode12BitPacked: %v", err)
	}
	if err := img.Validate(); err != nil {
		t.Fatalf("decoded frame invalid: %v", err)
	}
	// 8-bit values are the 12-bit samples shifted right by 4.
	want := []byte{0x23, 0x78, 0xc5, 0x9a, 0, 0, 0, 0}
	if !bytes.Equal(img.Pix, want) {
		t.Fatalf("Pix = % x, want % x", img.Pix, want)
	}
}

func TestDecode12BitPackedFullRange(t *testing.T) {
	// All bits set must map to 0xff, all clear to 0x00.
	raw := bytes.Repeat([]byte{0xff}, BytesPer12BitGroup)
	img, err := Decode12BitPacked(raw, 4, 1)
	if err != nil {
		t.Fatalf("Decode12BitPacked: %v", err)
	}
	for i, p := range img.Pix {
		if p != 0xff {
			t.Errorf("pixel %d = 0x%02x, want 0xff", i, p)
		}
	}
}

func TestDecode12BitPackedErrors(t *testing.T) {
	if _, err := Decode12BitPacked(make([]byte, 5), 4, 1); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("short frame: got %v, want ErrShortFrame", err)
	}
	if _, err := Decode12BitPacked(make([]byte, 60), 3, 1); err == nil {
		t.Fatal("expected error for sample count not divisible by 4")
	}
	if _, err := Decode12BitPacked(make([]byte, 60), 0, 4); err == nil {
		t.Fatal("expected error for zero width")
	}
}

// pack12Bit is the inverse of the Decode12BitRaw layout, defined only in the
// test so a round-trip can guard the (deliberately irregular) unpack against
// accidental change. samples must be a multiple of SamplesPer12BitGroup and
// each value must fit in 12 bits.
func pack12Bit(samples []uint16) []byte {
	out := make([]byte, 0, len(samples)/SamplesPer12BitGroup*BytesPer12BitGroup)
	for i := 0; i < len(samples); i += SamplesPer12BitGroup {
		s0, s1, s2, s3 := samples[i], samples[i+1], samples[i+2], samples[i+3]
		b0 := byte((s0>>8)&0x0f) | byte(s1&0x0f)<<4
		b1 := byte(s0)
		b2 := byte(s2)
		b3 := byte(s1 >> 4)
		b4 := byte(s3 >> 4)
		b5 := byte((s2>>8)&0x0f) | byte(s3&0x0f)<<4
		out = append(out, b0, b1, b2, b3, b4, b5)
	}
	return out
}

// Round-trip synthetic 12-bit samples through pack12Bit and Decode12BitRaw.
// The values cover the full 0..4095 range so every nibble position is
// exercised; no real sensor frame is involved.
func TestDecode12BitRawRoundTrip(t *testing.T) {
	const w, h = 80, 64 // 5120 samples, the believed 5120 geometry
	samples := make([]uint16, w*h)
	for i := range samples {
		samples[i] = uint16((i * 7) & 0x0fff) // spread across 0..4095
	}
	raw := pack12Bit(samples)
	if len(raw) != w*h/SamplesPer12BitGroup*BytesPer12BitGroup {
		t.Fatalf("packed %d bytes, want %d", len(raw), w*h/SamplesPer12BitGroup*BytesPer12BitGroup)
	}
	got, err := Decode12BitRaw(raw, w, h)
	if err != nil {
		t.Fatalf("Decode12BitRaw: %v", err)
	}
	if len(got) != len(samples) {
		t.Fatalf("got %d samples, want %d", len(got), len(samples))
	}
	for i := range samples {
		if got[i] != samples[i] {
			t.Fatalf("sample %d round-trips to 0x%03x, want 0x%03x", i, got[i], samples[i])
		}
	}
}

// The 5120 is believed to be 80x64 = 5120 pixels, 12-bit packed at four
// samples per six bytes = exactly 7680 bytes of plaintext (see docs/protocol.md
// "How big is an image, really"). This pins that arithmetic and the pixel count
// with synthetic zero data; the 12-bit packing itself remains a hypothesis.
func TestDecode12Bit80x64(t *testing.T) {
	const w, h = 80, 64
	const wantBytes = 7680
	const wantPixels = 5120
	if w*h != wantPixels {
		t.Fatalf("%dx%d = %d, want %d pixels", w, h, w*h, wantPixels)
	}
	if got := w * h / SamplesPer12BitGroup * BytesPer12BitGroup; got != wantBytes {
		t.Fatalf("packed size %d, want %d bytes", got, wantBytes)
	}
	img, err := Decode12BitPacked(make([]byte, wantBytes), w, h)
	if err != nil {
		t.Fatalf("Decode12BitPacked: %v", err)
	}
	if len(img.Pix) != wantPixels {
		t.Fatalf("got %d pixels, want %d", len(img.Pix), wantPixels)
	}
}

// A buffer exactly one byte short of a full group must fail; the exact length
// must succeed. Guards the len(raw) < need boundary.
func TestDecode12BitLengthBoundary(t *testing.T) {
	const w, h = 4, 1 // one group, 6 bytes
	if _, err := Decode12BitRaw(make([]byte, BytesPer12BitGroup-1), w, h); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("one byte short: got %v, want ErrShortFrame", err)
	}
	if _, err := Decode12BitRaw(make([]byte, BytesPer12BitGroup), w, h); err != nil {
		t.Fatalf("exact length: unexpected error %v", err)
	}
	// Trailing bytes beyond the needed count are tolerated: the decoder reads
	// only the leading need bytes, so a caller must strip any header/trailer
	// (e.g. upstream's 8-byte header + 5-byte trailer) before decoding.
	got, err := Decode12BitRaw(make([]byte, BytesPer12BitGroup+13), w, h)
	if err != nil {
		t.Fatalf("trailing bytes: unexpected error %v", err)
	}
	if len(got) != w*h {
		t.Fatalf("got %d samples, want %d", len(got), w*h)
	}
}

// The upstream 51x0 driver reads 10573 bytes from the TLS server, strips an
// 8-byte header and a 5-byte trailer, and decodes the remaining 10560 bytes as
// an 80x88 frame. This checks our decoder agrees on the arithmetic, without
// baking 80x88 in as the 5120's resolution (which is unknown).
func TestUpstreamFrameSizeArithmetic(t *testing.T) {
	const payload = 10573 - 8 - 5
	const w, h = 80, 88
	if payload != w*h/SamplesPer12BitGroup*BytesPer12BitGroup {
		t.Fatalf("payload %d does not match %dx%d packed at 12 bits", payload, w, h)
	}
	img, err := Decode12BitPacked(make([]byte, payload), w, h)
	if err != nil {
		t.Fatalf("Decode12BitPacked: %v", err)
	}
	if len(img.Pix) != w*h {
		t.Fatalf("got %d pixels, want %d", len(img.Pix), w*h)
	}
}
