package evtx

import (
	"bytes"
	"encoding/binary"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

// realLog points the optional end-to-end test at the vendor debug log. The log
// is gitignored and holds the device OTP, so it is never required: without this
// flag the suite still covers the whole parser, over bytes built here.
var realLog = flag.String("log", "", "path to Goodix-FingerprintProvider%4Debug.evtx for TestAgainstRealLog")

// --- an EVTX builder, so the tests need no fixture file ---

func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

// value writes one substitution value the way EVTX does: a uint16 character
// count, then the characters. The count is what stripLengthPrefix has to undo
// whenever it lands in printable ASCII.
func value(s string) []byte {
	out := binary.LittleEndian.AppendUint16(nil, uint16(len([]rune(s))))
	return append(out, utf16le(s)...)
}

// separator stands in for the binary-XML machinery between two values: token
// bytes, type codes, template ids. Anything non-printable ends a run.
func separator() []byte { return []byte{0x00, 0x00, 0x0d, 0x01} }

func body(values ...string) []byte {
	var b []byte
	for _, v := range values {
		b = append(b, separator()...)
		b = append(b, value(v)...)
	}
	return append(b, separator()...)
}

// record wraps a body in the record header and the trailing size copy.
func record(id, filetime uint64, body []byte) []byte {
	// Pad until the record is 8-byte aligned and at least minRecordLen.
	size := recordHeaderLen + len(body) + 4
	for size%recordAlign != 0 || size < minRecordLen {
		body = append(body, 0)
		size = recordHeaderLen + len(body) + 4
	}

	out := make([]byte, 0, size)
	out = binary.LittleEndian.AppendUint32(out, recordMagic)
	out = binary.LittleEndian.AppendUint32(out, uint32(size))
	out = binary.LittleEndian.AppendUint64(out, id)
	out = binary.LittleEndian.AppendUint64(out, filetime)
	out = append(out, body...)
	return binary.LittleEndian.AppendUint32(out, uint32(size))
}

// fileHeader builds the 4096-byte header block.
func fileHeader(first, last, next uint64, chunks uint16) []byte {
	h := make([]byte, 4096)
	copy(h, headerMagic)
	binary.LittleEndian.PutUint64(h[offFirstChunk:], first)
	binary.LittleEndian.PutUint64(h[offLastChunk:], last)
	binary.LittleEndian.PutUint64(h[offNextRecord:], next)
	binary.LittleEndian.PutUint32(h[offHeaderSize:], headerLen)
	binary.LittleEndian.PutUint16(h[offMinor:], 2)
	binary.LittleEndian.PutUint16(h[offMajor:], 3)
	binary.LittleEndian.PutUint16(h[offBlockSize:], 0x1000)
	binary.LittleEndian.PutUint16(h[offChunkCount:], chunks)
	return h
}

// fileTimeOf is the inverse of FileTime, for building fixtures.
func fileTimeOf(t time.Time) uint64 {
	return uint64((t.Unix() + filetimeToUnix)) * 1e7
}

// theMessage is a real line from the log, of a length whose character count
// (34) is the printable ASCII '"'. That is not incidental: it is the case
// stripLengthPrefix exists for.
const theMessage = " Send data::0xa00600a696030001020e"

func TestScanRecoversARecord(t *testing.T) {
	when := time.Date(2026, 9, 19, 23, 25, 41, 0, time.UTC)

	var buf bytes.Buffer
	buf.Write(fileHeader(28, 27, 264318, 320))
	buf.Write(record(263055, fileTimeOf(when),
		body("Driver", "GoodixFingerprintEngineProvider", theMessage)))

	recs := Scan(buf.Bytes())
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]

	if r.ID != 263055 {
		t.Errorf("ID = %d, want 263055", r.ID)
	}
	if !r.Time.Equal(when) {
		t.Errorf("Time = %s, want %s", r.Time, when)
	}
	want := []string{"Driver", "GoodixFingerprintEngineProvider", theMessage}
	if len(r.Strings) != len(want) {
		t.Fatalf("Strings = %q, want %q", r.Strings, want)
	}
	for i := range want {
		if r.Strings[i] != want[i] {
			t.Errorf("Strings[%d] = %q, want %q", i, r.Strings[i], want[i])
		}
	}
	if got := r.Message(); got != strings.TrimSpace(theMessage) {
		t.Errorf("Message() = %q, want the last value, trimmed", got)
	}
	if r.Redacted {
		t.Error("a host-sent frame was redacted; only the 0xe4 and 0xa6 replies are")
	}
}

// TestTrailingSizeMismatchIsRejected covers the one check that separates a
// record from a coincidence. A 20 MB log of hex dumps contains the record magic
// by accident; if the trailing size were not verified, those become records
// with invented ids and timestamps.
func TestTrailingSizeMismatchIsRejected(t *testing.T) {
	good := record(1, fileTimeOf(time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)), body("Driver", theMessage))

	bad := bytes.Clone(good)
	binary.LittleEndian.PutUint32(bad[len(bad)-4:], uint32(len(bad))+8)
	if recs := Scan(bad); len(recs) != 0 {
		t.Errorf("a record whose trailing size disagrees was accepted: %+v", recs)
	}

	// The same bytes with the trailing size restored must still parse, so the
	// test above is not passing for some unrelated reason.
	if recs := Scan(good); len(recs) != 1 {
		t.Fatalf("the control record did not parse: got %d records, want 1", len(recs))
	}
}

// TestTruncatedRecordAtEndIsIgnored: an EVTX file that was still being written
// ends mid-record. That must neither panic nor yield a record built from bytes
// that are not there.
func TestTruncatedRecordAtEndIsIgnored(t *testing.T) {
	when := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	whole := record(7, fileTimeOf(when), body("Driver", theMessage))
	tail := record(8, fileTimeOf(when.Add(time.Second)), body("Driver", theMessage))

	for _, cut := range []int{1, 8, 16, len(tail) / 2, len(tail) - 4, len(tail) - 1} {
		var buf bytes.Buffer
		buf.Write(fileHeader(0, 0, 9, 320))
		buf.Write(whole)
		buf.Write(tail[:len(tail)-cut])

		recs := Scan(buf.Bytes()) // must not panic
		if len(recs) != 1 {
			t.Errorf("cutting %d bytes off the last record gave %d records, want 1", cut, len(recs))
			continue
		}
		if recs[0].ID != 7 {
			t.Errorf("cutting %d bytes gave record id %d, want the intact record 7", cut, recs[0].ID)
		}
	}
}

func TestFileTimeKnownValue(t *testing.T) {
	// 2020-09-13 12:26:40 UTC is Unix 1600000000, so the FILETIME is
	// (1600000000 + 11644473600) * 10^7.
	const ft = 132444736000000000
	got := FileTime(ft)
	want := time.Date(2020, 9, 13, 12, 26, 40, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("FileTime(%d) = %s, want %s", uint64(ft), got, want)
	}

	// The FILETIME epoch itself, which is where an off-by-one in the constant
	// would show up as a 1601 date drifting.
	if got := FileTime(0); got.Year() != 1601 || got.Month() != 1 || got.Day() != 1 {
		t.Errorf("FileTime(0) = %s, want 1601-01-01", got)
	}

	// Sub-second precision: 100 ns ticks must survive.
	if got := FileTime(ft + 1234567); got.Nanosecond() != 123456700 {
		t.Errorf("FileTime kept %d ns, want 123456700", got.Nanosecond())
	}
}

// TestInRangeBoundsAreInclusive pins what -from and -to mean. "From 23:25:41"
// has to include a record stamped 23:25:41 exactly, or reading an init out of
// the log by its start time silently drops its first frame.
func TestInRangeBoundsAreInclusive(t *testing.T) {
	at := func(s int) Record {
		return Record{Time: time.Date(2026, 9, 19, 23, 25, s, 0, time.UTC)}
	}
	lo, hi := at(10).Time, at(20).Time

	for _, tc := range []struct {
		sec  int
		want bool
	}{{9, false}, {10, true}, {15, true}, {20, true}, {21, false}} {
		if got := at(tc.sec).InRange(lo, hi); got != tc.want {
			t.Errorf("second %d in [10,20] = %v, want %v", tc.sec, got, tc.want)
		}
	}

	// A zero bound is unbounded on that side.
	if !at(0).InRange(time.Time{}, hi) {
		t.Error("a zero lower bound excluded a record")
	}
	if !at(99).InRange(lo, time.Time{}) {
		t.Error("a zero upper bound excluded a record")
	}
}

func TestParseHeaderReportsWrapping(t *testing.T) {
	// The real file: 320 chunks, oldest chunk 28, newest 27.
	h, err := ParseHeader(fileHeader(28, 27, 264318, 320))
	if err != nil {
		t.Fatal(err)
	}
	if h.Chunks != 320 || h.FirstChunk != 28 || h.LastChunk != 27 {
		t.Errorf("header = %+v, want 320 chunks, first 28, last 27", h)
	}
	if h.Major != 3 || h.Minor != 2 {
		t.Errorf("version = %d.%d, want 3.2", h.Major, h.Minor)
	}
	if !h.Wrapped() {
		t.Error("a log whose oldest chunk sits past its newest was not reported as wrapped")
	}

	h, err = ParseHeader(fileHeader(0, 41, 9000, 320))
	if err != nil {
		t.Fatal(err)
	}
	if h.Wrapped() {
		t.Error("a log still filling chunk 41 of 320 was reported as wrapped")
	}

	bad := fileHeader(0, 0, 0, 320)
	copy(bad, "NotEvtx\x00")
	if _, err := ParseHeader(bad); err == nil {
		t.Error("a file with the wrong magic was accepted")
	}
	if _, err := ParseHeader([]byte{1, 2, 3}); err == nil {
		t.Error("a file shorter than the header was accepted")
	}
}

func TestStripLengthPrefix(t *testing.T) {
	// The observed case: '(' is 40, and 40 characters follow.
	const run = "( Send data::0xa00900a9ae060055aa370000c0"
	if got := stripLengthPrefix(run); got != run[1:] {
		t.Errorf("stripLengthPrefix(%q) = %q, want the run without its count", run, got)
	}

	// A short value carries a count that is not printable, so it never reaches
	// the run in the first place and must be left alone.
	for _, s := range []string{"Driver", "enter", "exit, ret 0"} {
		if got := stripLengthPrefix(s); got != s {
			t.Errorf("stripLengthPrefix(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestSecretRepliesAreWithheld is the refusal, pinned. The log holds the whole
// 41-byte 0xe4 reply and the whole 64-byte 0xa6 reply in hex, which are the two
// payloads cmd/goodix-pcap already refuses to print.
func TestSecretRepliesAreWithheld(t *testing.T) {
	// Stand-in bytes; the real ones are not in this repository.
	const (
		pskHash = "e42a00" + "1122334455667788990011223344556677889900112233445566778899001122334455667788990011"
		otp     = "a64100" + "5332413735352e00"
		sensor  = "5332413735352e001122334455667788"
	)

	cases := []struct {
		name, in, mustNotHold string
	}{
		{"the 0xe4 reply", " data::0x" + pskHash, pskHash[6:]},
		{"the 0xa6 reply", " data::0x" + otp, otp[6:]},
		{"an OTP dump", " Got sensor OTP::0x" + sensor, sensor},
		{"a lower-case OTP dump", " got file otp::0x" + sensor, sensor},
		{"the sensor id", " sensorid:0x" + sensor, sensor},
	}
	for _, tc := range cases {
		got, hidden := Redact(tc.in)
		if !hidden {
			t.Errorf("%s: Redact reported nothing withheld", tc.name)
		}
		if strings.Contains(got, tc.mustNotHold) {
			t.Errorf("%s: the payload survived redaction: %q", tc.name, got)
		}
		if !strings.Contains(got, "withheld") {
			t.Errorf("%s: the redaction is silent; it must say what it removed: %q", tc.name, got)
		}
	}

	// What must NOT be withheld: the frames the host sends. The 224-byte 0x90
	// config and the whole init sequence live in these, and reproducing them is
	// the reason this tool exists.
	keep := []string{
		" Send data::0xa00600a696030001020e",
		" Send data::0xa00c00ace40900030002bb00000000fd", // the 0xe4 REQUEST
		" recvd data cmd-len: 0xe4-42",
		" test::0x506a09000000000079f7739faa7acacbff",
		" received fdt base::0xabbabb8b7bb7a4bcba3b0bacd7",
	}
	for _, s := range keep {
		got, hidden := Redact(s)
		if hidden || got != s {
			t.Errorf("Redact(%q) = %q (withheld=%v), want it untouched", s, got, hidden)
		}
	}
}

// The refusal has to survive Scan, because Scan is where it happens: there is
// no path through this package that yields the unredacted bytes.
func TestScanRedactsBeforeBuildingARecord(t *testing.T) {
	const reply = " data::0xe42a001122334455667788990011223344556677889900112233445566778899001122334455"

	var buf bytes.Buffer
	buf.Write(fileHeader(0, 0, 2, 320))
	buf.Write(record(1, fileTimeOf(time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)), body("Driver", reply)))

	recs := Scan(buf.Bytes())
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if !recs[0].Redacted {
		t.Error("the record was not marked as redacted")
	}
	if strings.Contains(recs[0].Text(), "1122334455") {
		t.Errorf("the PSK-hash payload reached a Record: %q", recs[0].Text())
	}
	// The opcode and declared length survive: the log states both in clear on
	// the neighbouring "recvd data cmd-len:" line anyway.
	if !strings.Contains(recs[0].Text(), "data::0xe42a00[") {
		t.Errorf("the opcode and length were withheld too, which hides nothing: %q", recs[0].Text())
	}
}

func TestShapeCollapsesValues(t *testing.T) {
	cases := []struct{ in, want string }{
		{" recvd data cmd-len: 0xe4-42", "recvd data cmd-len: HEX-N"},
		{"exit, status: 0x0, bret:1", "exit, status: HEX, bret:N"},
		{"enter\t  spaced   out", "enter spaced out"},
		{"S0Idle: 10s, switch 0", "SNIdle: Ns, switch N"},
	}
	for _, tc := range cases {
		if got := Shape(tc.in); got != tc.want {
			t.Errorf("Shape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// The placeholders must not contain a digit, or the number pass rewrites
	// the hex pass's own output.
	if got := Shape("test::0xdeadbeef"); strings.ContainsAny(got, "0123456789") {
		t.Errorf("Shape produced %q, which still holds a digit", got)
	}

	// A shape is a grouping key, not a quotation, so it is bounded.
	long := "a::0x" + strings.Repeat("ab", 400)
	if n := len([]rune(Shape(long))); n > shapeMax+3 {
		t.Errorf("Shape returned %d characters, want at most %d", n, shapeMax+3)
	}
}

func TestSummariseCounts(t *testing.T) {
	base := time.Date(2026, 9, 19, 23, 25, 41, 0, time.UTC)
	recs := []Record{
		{ID: 10, Time: base, Strings: []string{"Driver", "enter"}},
		{ID: 11, Time: base.Add(time.Second), Strings: []string{"Driver", "enter"}},
		{ID: 12, Time: base.Add(2 * time.Second), Strings: []string{"Driver", "exit, ret 1"}},
		{ID: 13, Time: base.Add(3 * time.Second), Strings: []string{"Driver", "x"}, Redacted: true},
	}

	s := Summarise(recs)
	if s.Records != 4 {
		t.Errorf("Records = %d, want 4", s.Records)
	}
	if s.FirstID != 10 || s.LastID != 13 {
		t.Errorf("ids %d..%d, want 10..13", s.FirstID, s.LastID)
	}
	if !s.First.Equal(base) || !s.Last.Equal(base.Add(3*time.Second)) {
		t.Errorf("span %s .. %s, want %s .. %s", s.First, s.Last, base, base.Add(3*time.Second))
	}
	if s.Redacted != 1 {
		t.Errorf("Redacted = %d, want 1", s.Redacted)
	}

	top := s.TopShapes(2)
	if len(top) != 2 {
		t.Fatalf("TopShapes(2) returned %d shapes", len(top))
	}
	if top[0].Shape != "enter" || top[0].Count != 2 {
		t.Errorf("most common shape = %+v, want enter x2", top[0])
	}

	if got := Summarise(nil); got.Records != 0 || got.Shapes == nil {
		t.Errorf("Summarise(nil) = %+v, want an empty summary with usable maps", got)
	}
}

// TestScanSortsOldestFirst: a wrapped log's oldest chunk is not chunk 0, so
// file order is not time order. Reading the first record in the file as the
// start of the log is the mistake the 2026-09-20 recount had to undo.
func TestScanSortsOldestFirst(t *testing.T) {
	old := time.Date(2026, 8, 15, 17, 29, 14, 0, time.UTC)
	recent := time.Date(2026, 9, 19, 23, 27, 7, 0, time.UTC)

	var buf bytes.Buffer
	buf.Write(fileHeader(28, 27, 300, 320))
	buf.Write(record(290, fileTimeOf(recent), body("Driver", theMessage))) // newest chunk first in the file
	buf.Write(record(100, fileTimeOf(old), body("Driver", theMessage)))

	recs := Scan(buf.Bytes())
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].ID != 100 || recs[1].ID != 290 {
		t.Errorf("order = %d, %d; want the older record first", recs[0].ID, recs[1].ID)
	}
}

// TestAgainstRealLog re-derives the figures docs/protocol.md records. It runs
// only when the log is supplied, because the log is gitignored — but when it
// runs, a disagreement here means the documentation is wrong, which matters
// more than this package does.
func TestAgainstRealLog(t *testing.T) {
	if *realLog == "" {
		t.Skip("no -log given; the vendor debug log is gitignored")
	}

	b, err := os.ReadFile(*realLog)
	if err != nil {
		t.Fatal(err)
	}

	h, err := ParseHeader(b)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if !h.Wrapped() {
		t.Errorf("header = %+v, want a wrapped log (first chunk past last)", h)
	}

	recs := Scan(b)
	t.Logf("%d records, %s .. %s, header %+v",
		len(recs), recs[0].Time, recs[len(recs)-1].Time, h)

	// The figures docs/protocol.md states, recounted 2026-09-20.
	const wantRecords = 17545
	if len(recs) != wantRecords {
		t.Errorf("%d records, but docs/protocol.md says %d — one of the two is wrong",
			len(recs), wantRecords)
	}

	first := recs[0].Time.UTC().Format("2006-01-02 15:04:05")
	last := recs[len(recs)-1].Time.UTC().Format("2006-01-02 15:04:05")
	if first != "2026-08-15 15:29:14" || last != "2026-09-19 21:27:07" {
		t.Errorf("span %s .. %s UTC, but docs/protocol.md says 2026-08-15 17:29:14 .. 2026-09-19 23:27:07 local (CEST, UTC+2)",
			first, last)
	}

	// An init is a "Initialization done successfully"; a complete one also sends
	// the 224-byte 0x90 config, which is the only `Send data::0xa0e4…` frame.
	inits, complete := 0, 0
	for _, r := range recs {
		text := r.Text()
		if strings.Contains(text, "Initialization done successfully") {
			inits++
		}
		if strings.Contains(text, "Send data::0xa0e4") {
			complete++
		}
	}
	if inits != 18 || complete != 9 {
		t.Errorf("%d inits of which %d complete, but docs/protocol.md says 18 and 9", inits, complete)
	}

	// Nothing may print the OTP. Its first seven characters are published
	// deliberately; the bytes behind them are not.
	for _, r := range recs {
		if strings.Contains(r.Text(), "5332413735352e") {
			t.Fatalf("record %d reproduces the device OTP: %q", r.ID, Shape(r.Message()))
		}
	}
}
