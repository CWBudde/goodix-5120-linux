package image

import (
	"bytes"
	"errors"
	"testing"
)

// TestPackedLenForThisPart pins the arithmetic the whole Phase 5c expectation
// rests on: 80 x 64 = 5120 samples at four per six bytes is 7680 bytes exactly,
// and with upstream's header and trailer, 7693. Both fit inside the 7744-byte
// record observed on the wire, which is why the length alone cannot tell them
// apart (docs/protocol.md, "How big is an image, really").
func TestPackedLenForThisPart(t *testing.T) {
	got, err := PackedLen(80, 64)
	if err != nil {
		t.Fatalf("PackedLen(80, 64) = %v", err)
	}
	if got != 7680 {
		t.Errorf("PackedLen(80, 64) = %d, want 7680", got)
	}
	if wrapped := got + FrameHeaderLen + FrameTrailerLen; wrapped != 7693 {
		t.Errorf("wrapped length = %d, want 7693", wrapped)
	}

	// Upstream's own part, as a cross-check on the formula: driver_51x0.py keeps
	// 10560 bytes for 80 x 88.
	if got, err := PackedLen(80, 88); err != nil || got != 10560 {
		t.Errorf("PackedLen(80, 88) = %d, %v; want 10560, nil", got, err)
	}
}

func TestTrimFrameRecognisesBothLayouts(t *testing.T) {
	const w, h = 80, 64
	need, err := PackedLen(w, h)
	if err != nil {
		t.Fatal(err)
	}

	samples := make([]byte, need)
	for i := range samples {
		samples[i] = byte(i*3 + 1)
	}

	t.Run("bare", func(t *testing.T) {
		got, layout, err := TrimFrame(samples, w, h)
		if err != nil {
			t.Fatalf("TrimFrame = %v", err)
		}
		if layout != LayoutBare {
			t.Errorf("layout = %v, want bare", layout)
		}
		if !bytes.Equal(got, samples) {
			t.Error("the samples were altered")
		}
	})

	t.Run("wrapped", func(t *testing.T) {
		wrapped := make([]byte, 0, need+FrameHeaderLen+FrameTrailerLen)
		wrapped = append(wrapped, bytes.Repeat([]byte{0xaa}, FrameHeaderLen)...)
		wrapped = append(wrapped, samples...)
		wrapped = append(wrapped, bytes.Repeat([]byte{0xbb}, FrameTrailerLen)...)

		got, layout, err := TrimFrame(wrapped, w, h)
		if err != nil {
			t.Fatalf("TrimFrame = %v", err)
		}
		if layout != LayoutWrapped {
			t.Errorf("layout = %v, want wrapped", layout)
		}
		if !bytes.Equal(got, samples) {
			t.Error("the header or trailer was not stripped cleanly")
		}
	})
}

// TestTrimFrameRefusesToGuess is the point of the function. A frame decoded from
// the wrong offset still looks like a fingerprint, so a wrong guess here would
// not be visible in the output — it has to be an error instead.
func TestTrimFrameRefusesToGuess(t *testing.T) {
	const w, h = 80, 64
	need, _ := PackedLen(w, h)

	t.Run("short", func(t *testing.T) {
		_, _, err := TrimFrame(make([]byte, need-1), w, h)
		if !errors.Is(err, ErrShortFrame) {
			t.Fatalf("TrimFrame of a short frame = %v, want ErrShortFrame", err)
		}
	})

	for _, n := range []int{need + 1, need + 12, need + 14, need + 64} {
		_, _, err := TrimFrame(make([]byte, n), w, h)
		if err == nil {
			t.Errorf("TrimFrame accepted %d bytes, which matches neither layout", n)
		}
		if errors.Is(err, ErrShortFrame) {
			t.Errorf("TrimFrame(%d bytes) reported a short frame; it is longer than either layout", n)
		}
	}
}

// TestTrimFrameThenDecode is the shape the Phase 5c capture takes: trim, then
// decode, and the sample count must come out at width x height.
func TestTrimFrameThenDecode(t *testing.T) {
	const w, h = 80, 64
	need, _ := PackedLen(w, h)

	wrapped := make([]byte, need+FrameHeaderLen+FrameTrailerLen)
	for i := range wrapped {
		wrapped[i] = byte(i % 251)
	}

	trimmed, layout, err := TrimFrame(wrapped, w, h)
	if err != nil {
		t.Fatalf("TrimFrame = %v", err)
	}
	samples, err := Decode12BitRaw(trimmed, w, h)
	if err != nil {
		t.Fatalf("Decode12BitRaw after TrimFrame (%v) = %v", layout, err)
	}
	if len(samples) != w*h {
		t.Fatalf("decoded %d samples, want %d", len(samples), w*h)
	}
	for i, s := range samples {
		if s > 0x0fff {
			t.Fatalf("sample %d is 0x%04x, which is more than 12 bits", i, s)
		}
	}
}
