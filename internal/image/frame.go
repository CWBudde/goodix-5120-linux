package image

import "fmt"

// Upstream's image frame wraps the packed samples in a small header and
// trailer. TRANSCRIBED from goodix-fp-dump driver_51x0.py, which reads 10573
// bytes, drops the first 8 and the last 5, and decodes the 10560 that remain
// (10560 = 80 x 88 / 4 x 6). Nothing is known about what either part contains.
const (
	FrameHeaderLen  = 8
	FrameTrailerLen = 5
)

// PackedLen is the number of bytes a width x height frame of 12-bit samples
// occupies, packed four samples per six bytes. For this part, 80 x 64, it is
// 7680.
func PackedLen(width, height int) (int, error) {
	if width <= 0 || height <= 0 {
		return 0, fmt.Errorf("image: invalid dimensions %dx%d", width, height)
	}
	count := width * height
	if count%SamplesPer12BitGroup != 0 {
		return 0, fmt.Errorf("image: %dx%d = %d samples is not a multiple of %d",
			width, height, count, SamplesPer12BitGroup)
	}
	return count / SamplesPer12BitGroup * BytesPer12BitGroup, nil
}

// FrameLayout says how a decrypted frame was laid out.
type FrameLayout int

const (
	// LayoutBare means the plaintext is nothing but packed samples.
	LayoutBare FrameLayout = iota
	// LayoutWrapped means the samples were surrounded by upstream's 8-byte
	// header and 5-byte trailer.
	LayoutWrapped
)

func (l FrameLayout) String() string {
	switch l {
	case LayoutBare:
		return "bare samples"
	case LayoutWrapped:
		return fmt.Sprintf("samples wrapped in a %d-byte header and a %d-byte trailer", FrameHeaderLen, FrameTrailerLen)
	default:
		return fmt.Sprintf("unknown layout %d", int(l))
	}
}

// TrimFrame returns just the packed samples from a decrypted frame, and which of
// the two known layouts it had.
//
// Which layout the 5120 uses is an OPEN QUESTION that only a real plaintext
// settles (PLAN.md Phase 5c). The record length observed on the wire — 7744
// bytes of ciphertext — is consistent with both: 7680 bare samples or 7693
// samples plus upstream's header and trailer both fit inside it
// (docs/protocol.md, "How big is an image, really"). So rather than assume,
// this decides from the length that actually arrives, and refuses to guess when
// it is neither.
//
// The returned slice aliases plain.
func TrimFrame(plain []byte, width, height int) ([]byte, FrameLayout, error) {
	need, err := PackedLen(width, height)
	if err != nil {
		return nil, 0, err
	}
	wrapped := need + FrameHeaderLen + FrameTrailerLen

	switch len(plain) {
	case need:
		return plain, LayoutBare, nil
	case wrapped:
		return plain[FrameHeaderLen : FrameHeaderLen+need], LayoutWrapped, nil
	}

	if len(plain) < need {
		return nil, 0, fmt.Errorf("%w: %d plaintext byte(s) for %dx%d, which needs %d bare or %d wrapped",
			ErrShortFrame, len(plain), width, height, need, wrapped)
	}
	// Longer than either and matching neither. Refusing beats picking an offset:
	// a frame decoded from the wrong offset still looks like a fingerprint, so
	// the mistake would not be visible in the output.
	return nil, 0, fmt.Errorf("image: %d plaintext byte(s) for %dx%d match neither known layout "+
		"(%d bare, %d wrapped); record the length in docs/protocol.md rather than guessing an offset",
		len(plain), width, height, need, wrapped)
}
