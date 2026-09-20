package evtx

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

// Summary counts what a log contains without reproducing a message from it.
//
// It is what to look at first, and by default all a caller gets: the driver's
// debug log is not biometric, but it names the machine, the driver build and
// every frame the driver exchanged, and dumping 17545 of those to a terminal
// because somebody wanted a record count is not a reasonable default.
type Summary struct {
	Records         int
	FirstID, LastID uint64
	First, Last     time.Time
	Redacted        int
	Shapes          map[string]int
	PerHour         map[string]int
}

// ShapeCount is one message shape and how often it occurred.
type ShapeCount struct {
	Shape string
	Count int
}

// Summarise reduces records to counts.
func Summarise(recs []Record) Summary {
	s := Summary{Shapes: map[string]int{}, PerHour: map[string]int{}}
	if len(recs) == 0 {
		return s
	}

	s.Records = len(recs)
	s.First, s.Last = recs[0].Time, recs[len(recs)-1].Time
	s.FirstID, s.LastID = recs[0].ID, recs[0].ID
	for _, r := range recs {
		if r.ID < s.FirstID {
			s.FirstID = r.ID
		}
		if r.ID > s.LastID {
			s.LastID = r.ID
		}
		if r.Redacted {
			s.Redacted++
		}
		s.Shapes[Shape(r.Message())]++
		s.PerHour[r.Time.Local().Format("2006-01-02 15h")]++
	}
	return s
}

// TopShapes returns the n most common shapes, most common first, with ties
// broken alphabetically so the output is stable between runs.
func (s Summary) TopShapes(n int) []ShapeCount {
	out := make([]ShapeCount, 0, len(s.Shapes))
	for sh, c := range s.Shapes {
		out = append(out, ShapeCount{sh, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Shape < out[j].Shape
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Hours returns the per-hour histogram keys in order. Where a log has coverage
// is a different question from what span it covers: this log spans five weeks
// and has records in eleven hours of them.
func (s Summary) Hours() []string {
	out := make([]string, 0, len(s.PerHour))
	for k := range s.PerHour {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	hexLiteral = regexp.MustCompile(`(?i)0x[0-9a-f]+`)
	digits     = regexp.MustCompile(`[0-9]+`)
	spaces     = regexp.MustCompile(`\s+`)
)

// shapeMax bounds a shape. A shape is a grouping key, not a quotation, and a
// short one groups better; it is also the only message-derived text the default
// output prints, so it should not be long enough to carry a payload.
const shapeMax = 64

// Shape reduces a message to the skeleton it shares with every other instance
// of the same log line: hex literals become HEX, decimal numbers become N,
// runs of whitespace collapse, and the result is truncated.
//
// The placeholders deliberately contain no digit. "0xH" would be rewritten to
// "NxH" by the very next substitution, which is how the first draft of this
// function reported 2395 occurrences of "test::NxH".
//
// This is what makes a 17545-record log legible in twenty lines. It is not a
// redaction — Redact has already run, in Scan — but it does mean the default
// summary quotes no value from any record, only the wording around it.
func Shape(msg string) string {
	s := hexLiteral.ReplaceAllString(msg, "HEX")
	s = digits.ReplaceAllString(s, "N")
	s = strings.TrimSpace(spaces.ReplaceAllString(s, " "))

	r := []rune(s)
	if len(r) > shapeMax {
		return string(r[:shapeMax]) + "..."
	}
	return s
}
