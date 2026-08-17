// Package image holds the raw sensor frame representation for the Goodix
// 27c6:5120 fingerprint sensor plus the helpers needed to turn a frame into
// something a human can look at.
//
// Tier 2 scaffolding: nothing in the shipped Tier 1 probe calls this package.
package image

import (
	"errors"
	"fmt"
	"io"
)

// Gray8 is a raw 8-bit greyscale sensor frame stored row-major, top-left
// origin. Pix must hold exactly Width*Height samples.
type Gray8 struct {
	Width, Height int
	Pix           []byte
}

// Validate reports whether the frame is internally consistent.
func (g Gray8) Validate() error {
	if g.Width <= 0 {
		return fmt.Errorf("image: invalid width %d", g.Width)
	}
	if g.Height <= 0 {
		return fmt.Errorf("image: invalid height %d", g.Height)
	}
	want := g.Width * g.Height
	if len(g.Pix) != want {
		return fmt.Errorf("image: pixel buffer length %d does not match %dx%d (%d)",
			len(g.Pix), g.Width, g.Height, want)
	}
	return nil
}

// WritePGM writes img as a binary (P5) portable greymap with a maximum
// sample value of 255.
//
// Note this deliberately differs from the upstream Python reference
// (goodix-fp-dump tool.py write_pgm), which emits ASCII P2 with maxval 4095
// and additionally swaps the width and height fields in the header. We emit a
// spec-compliant P5 file with the dimensions in the conventional order.
func WritePGM(w io.Writer, img Gray8) error {
	if err := img.Validate(); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "P5\n%d %d\n255\n", img.Width, img.Height); err != nil {
		return fmt.Errorf("image: writing PGM header: %w", err)
	}
	if _, err := w.Write(img.Pix); err != nil {
		return fmt.Errorf("image: writing PGM pixels: %w", err)
	}
	return nil
}

// ErrShortFrame is returned when the raw byte slice does not contain enough
// packed samples for the requested dimensions.
var ErrShortFrame = errors.New("image: raw frame too short for requested dimensions")

// BytesPer12BitGroup is the size of one packed group in the sensor stream.
// Each group carries SamplesPer12BitGroup samples.
const (
	BytesPer12BitGroup   = 6
	SamplesPer12BitGroup = 4
)

// Decode12BitPacked unpacks the sensor's 12-bit samples into 8-bit greyscale.
//
// Packing (CONFIRMED against upstream goodix-fp-dump tool.py decode_image at
// commit on branch master; the 51x0 driver feeds it the TLS-decrypted image
// payload verbatim). Every 6 input bytes b0..b5 yield 4 twelve-bit samples:
//
//	s0 = (b0 & 0x0f) << 8 | b1
//	s1 = b3 << 4         | b0 >> 4
//	s2 = (b5 & 0x0f) << 8 | b2
//	s3 = b4 << 4         | b5 >> 4
//
// Note the ordering is genuinely irregular — it is not a straight
// little/big-endian 12-bit stream — so do not "simplify" it.
//
// The 12-bit samples are reduced to 8 bits by taking the high 8 bits
// (value >> 4). That truncation is OUR choice, not upstream's: upstream keeps
// the full 12-bit range and writes maxval 4095 ASCII PGM. Use Decode12BitRaw
// if you need the undiminished samples.
//
// INFERRED, not confirmed: that the 5120 uses the same packing as the 51x0
// family driver. It is the same generation and the same TLS image path, but it
// has not been checked against 5120 hardware. Dimensions are always caller
// supplied; nothing here assumes a resolution.
func Decode12BitPacked(raw []byte, width, height int) (Gray8, error) {
	samples, err := Decode12BitRaw(raw, width, height)
	if err != nil {
		return Gray8{}, err
	}
	pix := make([]byte, len(samples))
	for i, s := range samples {
		pix[i] = byte(s >> 4)
	}
	return Gray8{Width: width, Height: height, Pix: pix}, nil
}

// Decode12BitRaw unpacks the sensor stream into the full 12-bit sample values
// (0..4095) without reducing them to 8 bits. See Decode12BitPacked for the
// layout and for which parts are confirmed versus inferred.
func Decode12BitRaw(raw []byte, width, height int) ([]uint16, error) {
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("image: invalid dimensions %dx%d", width, height)
	}
	count := width * height
	if count%SamplesPer12BitGroup != 0 {
		return nil, fmt.Errorf("image: %dx%d = %d samples is not a multiple of %d",
			width, height, count, SamplesPer12BitGroup)
	}
	need := count / SamplesPer12BitGroup * BytesPer12BitGroup
	if len(raw) < need {
		return nil, fmt.Errorf("%w: have %d bytes, need %d for %dx%d",
			ErrShortFrame, len(raw), need, width, height)
	}

	out := make([]uint16, 0, count)
	for i := 0; i < need; i += BytesPer12BitGroup {
		c := raw[i : i+BytesPer12BitGroup]
		out = append(out,
			uint16(c[0]&0x0f)<<8|uint16(c[1]),
			uint16(c[3])<<4|uint16(c[0])>>4,
			uint16(c[5]&0x0f)<<8|uint16(c[2]),
			uint16(c[4])<<4|uint16(c[5])>>4,
		)
	}
	return out, nil
}
