package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestEvtxToolCannotReachHardware asserts this command cannot talk to a device.
// It reads a file and writes to stdout; that is the whole of it, and it is
// enforced here rather than left to intent.
func TestEvtxToolCannotReachHardware(t *testing.T) {
	allowed := map[string]bool{"goodix5120/internal/evtx": true}
	forbidden := []string{
		"goodix5120/internal/transport",
		"goodix5120/internal/proto",
		"github.com/google/gousb",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		checked++

		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import %s", e.Name(), imp.Path.Value)
			}
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports %q, which this command has no business needing", e.Name(), p)
				}
			}
			if strings.HasPrefix(p, "goodix5120/") && !allowed[p] {
				t.Errorf("%s imports %q, which is not on this command's allowlist", e.Name(), p)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files found; the test would pass vacuously")
	}
}

// --- output discipline, exercised through run() ---

// tinyLog writes a two-record EVTX file and returns its path. It is the
// smallest thing run() will accept, built here so the repository needs no
// .evtx fixture: a real one holds the device OTP.
func tinyLog(t *testing.T) string {
	t.Helper()

	filetime := fileTime(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))

	var buf bytes.Buffer
	buf.Write(evtxHeader())
	buf.Write(evtxRecord(1, filetime, " Send data::0xa00600a696030001020e"))
	buf.Write(evtxRecord(2, filetime+1e7, " data::0xe42a00"+strings.Repeat("ab", 41)))

	path := filepath.Join(t.TempDir(), "tiny.evtx")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fileTime is the inverse of the FILETIME conversion, for building fixtures:
// 100 ns ticks since 1601-01-01 UTC.
func fileTime(t time.Time) uint64 { return uint64(t.Unix()+11644473600) * 1e7 }

func evtxHeader() []byte {
	h := make([]byte, 4096)
	copy(h, "ElfFile\x00")
	put64(h[0x08:], 28) // first chunk
	put64(h[0x10:], 27) // last chunk: the log has wrapped
	put64(h[0x18:], 3)  // next record id
	put32(h[0x20:], 0x80)
	put16(h[0x24:], 2)      // minor
	put16(h[0x26:], 3)      // major
	put16(h[0x28:], 0x1000) // header block size
	put16(h[0x2a:], 320)    // chunks
	return h
}

func evtxRecord(id, filetime uint64, message string) []byte {
	var body []byte
	for _, v := range []string{"Driver", message} {
		body = append(body, 0, 0, 0x0d, 0x01)
		body = append(body, byte(len(v)), byte(len(v)>>8))
		for _, r := range v {
			body = append(body, byte(r), byte(r>>8))
		}
	}
	body = append(body, 0, 0, 0x0d, 0x01)

	size := 0x18 + len(body) + 4
	for size%8 != 0 || size < 0x30 {
		body = append(body, 0)
		size = 0x18 + len(body) + 4
	}

	out := make([]byte, 0, size)
	out = append(out, 0x2a, 0x2a, 0x00, 0x00)
	out = append(out, u32(uint32(size))...)
	out = append(out, u64(id)...)
	out = append(out, u64(filetime)...)
	out = append(out, body...)
	return append(out, u32(uint32(size))...)
}

func u16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func u32(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func u64(v uint64) []byte {
	out := make([]byte, 8)
	for i := range out {
		out[i] = byte(v >> (8 * i))
	}
	return out
}
func put16(b []byte, v uint16) { copy(b, u16(v)) }
func put32(b []byte, v uint32) { copy(b, u32(v)) }
func put64(b []byte, v uint64) { copy(b, u64(v)) }

func output(t *testing.T, o options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := run(log.New(&buf, "", 0), o); err != nil {
		t.Fatalf("run(%+v): %v", o, err)
	}
	return buf.String()
}

// TestDefaultOutputHoldsNoRecordText is the output discipline, pinned. The
// default is a summary: counts, ids, span, shapes. A caller who wants the log's
// text has to say so.
func TestDefaultOutputHoldsNoRecordText(t *testing.T) {
	out := output(t, options{path: tinyLog(t), limit: 50, shapes: 20})

	if strings.Contains(out, "0xa00600a696030001020e") {
		t.Errorf("the default output printed a frame:\n%s", out)
	}
	if !strings.Contains(out, "2 records") {
		t.Errorf("the default output does not report the record count:\n%s", out)
	}
	if !strings.Contains(out, "record ids 1..2") {
		t.Errorf("the default output does not report the id range:\n%s", out)
	}
	if !strings.Contains(out, "wrapped") {
		t.Errorf("the default output does not say the log has wrapped:\n%s", out)
	}
	// A shape is the skeleton, not the value.
	if !strings.Contains(out, "Send data::HEX") {
		t.Errorf("the default output does not list message shapes:\n%s", out)
	}
}

// TestTextNeedsAskingFor: -text and -grep are the two ways in, and -n bounds
// both of them.
func TestTextNeedsAskingFor(t *testing.T) {
	path := tinyLog(t)

	full := output(t, options{path: path, text: true, limit: 50, shapes: 5})
	if !strings.Contains(full, "0xa00600a696030001020e") {
		t.Errorf("-text printed no frame:\n%s", full)
	}

	filtered := output(t, options{path: path, grep: "send data", limit: 50, shapes: 5})
	if !strings.Contains(filtered, "0xa00600a696030001020e") {
		t.Errorf("-grep printed no matching record:\n%s", filtered)
	}
	if !strings.Contains(filtered, "1 records matched") {
		t.Errorf("-grep did not report how many records matched:\n%s", filtered)
	}

	bounded := output(t, options{path: path, text: true, limit: 1, shapes: 5})
	if !strings.Contains(bounded, "2 records matched, 1 printed") {
		t.Errorf("-n did not bound the output:\n%s", bounded)
	}
}

// TestSecretsSurviveEveryFlag: the 0xe4 reply is withheld by internal/evtx
// before a Record exists, so no flag here can ask for it. This is the end of
// that argument, checked rather than asserted.
func TestSecretsSurviveEveryFlag(t *testing.T) {
	path := tinyLog(t)
	payload := strings.Repeat("ab", 41)

	for _, o := range []options{
		{path: path, limit: 50, shapes: 20},
		{path: path, text: true, limit: 0, shapes: 20},
		{path: path, grep: "data", limit: 0, shapes: 20},
		{path: path, grep: payload, limit: 0, shapes: 20},
		{path: path, text: true, hours: true, limit: 0, shapes: 100},
	} {
		var buf bytes.Buffer
		// The payload-grep case matches nothing, which run() reports as an
		// error rather than silence; either way the bytes must not appear.
		_ = run(log.New(&buf, "", 0), o)
		if strings.Contains(buf.String(), payload) {
			t.Errorf("options %+v printed the withheld payload:\n%s", o, buf.String())
		}
	}
}

func TestTimeRangeAndBadInput(t *testing.T) {
	path := tinyLog(t)

	// 2026-09-19 12:00:00 UTC; the flags are local, so bound the whole day.
	out := output(t, options{path: path, from: "2026-09-19 00:00:00", to: "2026-09-20 00:00:00", limit: 50, shapes: 5})
	if !strings.Contains(out, "2 records") {
		t.Errorf("a range covering both records kept %s", out)
	}

	if err := run(log.New(&bytes.Buffer{}, "", 0), options{path: path, from: "yesterday", limit: 50}); err == nil {
		t.Error("an unparseable -from was accepted")
	}
	if err := run(log.New(&bytes.Buffer{}, "", 0), options{path: path, to: "2000-01-01 00:00:00", limit: 50}); err == nil {
		t.Error("a range holding no records was reported as success")
	}
	if err := run(log.New(&bytes.Buffer{}, "", 0), options{path: filepath.Join(t.TempDir(), "nope.evtx"), limit: 50}); err == nil {
		t.Error("a missing file was reported as success")
	}
}
