package evtx

import (
	"encoding/binary"
	"unicode"
)

// minRun is the shortest UTF-16LE run worth reporting. Below three characters
// almost everything is a coincidence: two adjacent little-endian uint16s in a
// template descriptor read as printable ASCII often enough to bury the real
// values.
const minRun = 3

// values pulls the substitution values out of a record body.
//
// It works because EVTX stores string values as plain UTF-16LE, contiguous and
// unescaped. Everything else in the body — template ids, value-type tables,
// lengths, offsets — is binary that does not survive the printable-ASCII test,
// so the runs that do survive are the values. This recovers what was logged
// without resolving a single template, and it is the whole reason this package
// can exist in a hundred lines instead of a thousand.
//
// Only ASCII is accepted. The driver logs ASCII, and admitting the rest of the
// BMP would let two-byte binary fields pass as CJK text and flood the output.
func values(b []byte) []string {
	var out []string
	var cur []rune

	flush := func() {
		if len(cur) >= minRun {
			out = append(out, stripLengthPrefix(string(cur)))
		}
		cur = nil
	}

	for i := 0; i+1 < len(b); i += 2 {
		c := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if c < 0x7f && (unicode.IsPrint(c) || c == '\t') {
			cur = append(cur, c)
			continue
		}
		flush()
	}
	flush()
	return out
}

// stripLengthPrefix drops the character count that EVTX writes immediately
// before a string value, when that count is itself printable ASCII and so gets
// swallowed into the run.
//
// Observed, 2026-09-20, on Goodix-FingerprintProvider%4Debug.evtx: the runs
// come out as `( Send data::0xa00900a9ae060055aa370000c0` and
// `1 data::0xa8110047465f...`, with one junk character in front. In every case
// checked the junk character's code equals the length of the rest of the run —
// '(' is 40 and 40 characters follow, '1' is 49 and 49 follow. It is the value's
// own uint16 length, in characters, landing in the range 32..126.
//
// This is therefore a format fact and not a cosmetic trim, but it is still a
// heuristic: a genuine value whose first character happened to equal its own
// remaining length would lose that character. The cost of the alternative is
// worse — without this, the same message appears under dozens of different
// leading characters and no two of them group together.
func stripLengthPrefix(s string) string {
	r := []rune(s)
	if len(r) < 2 || r[0] < 0x20 {
		return s
	}
	if int(r[0]) != len(r)-1 {
		return s
	}
	return string(r[1:])
}
