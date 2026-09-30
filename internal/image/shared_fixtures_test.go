package image

import (
	"bytes"
	"testing"

	"goodix5120/internal/testfixtures"
)

// A one-byte trim offset or reordered 12-bit sample can still look like a
// fingerprint. Assert every sample and pixel against hand-calculated literals.
func TestSharedImageLayouts(t *testing.T) {
	s := testfixtures.Load(t).Section(t, "image")
	w, h := s.Int(t, "width"), s.Int(t, "height")
	packed := bytes.Repeat(s.Hex(t, "pattern"), s.Int(t, "repetitions"))
	if len(packed) != s.Int(t, "packed_len") {
		t.Fatal("incomplete image reference")
	}
	expected := s.Ints(t, "samples")
	gray := s.Hex(t, "gray")
	if len(expected) != 4 || len(gray) != 4 {
		t.Fatal("incomplete sample group reference")
	}
	for _, wrapped := range []bool{false, true} {
		name := "bare"
		plain := packed
		offset := 0
		wantLayout := LayoutBare
		if wrapped {
			name = "wrapped"
			offset = len(s.Hex(t, "header"))
			wantLayout = LayoutWrapped
			plain = append(append(append([]byte{}, s.Hex(t, "header")...), packed...), s.Hex(t, "trailer")...)
		}
		t.Run(name, func(t *testing.T) {
			if wrapped && len(plain) != s.Int(t, "wrapped_len") {
				t.Fatal("incomplete wrapper")
			}
			raw, layout, err := TrimFrame(plain, w, h)
			if err != nil {
				t.Fatal(err)
			}
			if layout != wantLayout || len(raw) != len(packed) || &raw[0] != &plain[offset] || !bytes.Equal(raw, packed) {
				t.Fatal("wrong sample offset/layout")
			}
			samples, err := Decode12BitRaw(raw, w, h)
			if err != nil {
				t.Fatal(err)
			}
			img, err := Decode12BitPacked(raw, w, h)
			if err != nil {
				t.Fatal(err)
			}
			if len(samples) != w*h || len(img.Pix) != w*h || img.Width != w || img.Height != h {
				t.Fatal("wrong geometry")
			}
			for i, v := range samples {
				if int(v) != expected[i%len(expected)] || img.Pix[i] != gray[i%len(gray)] {
					t.Fatalf("sample %d = %03x/%02x", i, v, img.Pix[i])
				}
			}
		})
	}
	for _, n := range s.Ints(t, "rejected_lengths") {
		if _, _, err := TrimFrame(make([]byte, n), w, h); err == nil {
			t.Errorf("accepted %d-byte frame", n)
		}
	}
}
