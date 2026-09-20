package evtx

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// forbidden names every import that could put bytes on a USB bus.
var forbidden = []string{
	"goodix5120/internal/transport",
	"github.com/google/gousb",
}

// TestEvtxCannotReachHardware reads this package's own source and asserts its
// imports cannot reach a USB device.
//
// internal/capture is allowed one intra-repository import, internal/proto,
// because it decodes Goodix frames and needs the opcode registry. This package
// needs nothing: an EVTX record is a Windows format and knows nothing about
// this device. The allowlist is therefore empty, which is a stronger statement
// than internal/capture can make and should stay that way — if a later change
// wants proto here, that is a design decision to argue for, not a line to add.
//
// The point is structural, as it is in internal/capture: a tool that can only
// read a buffer cannot wedge the embedded controller, and after Runs 1, 2 and 4
// that has to be a property of the code rather than of anyone's intention.
func TestEvtxCannotReachHardware(t *testing.T) {
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
					t.Errorf("%s imports %q, which can talk to hardware", e.Name(), p)
				}
			}
			if strings.HasPrefix(p, "goodix5120/") {
				t.Errorf("%s imports %q; this package imports nothing from the repository", e.Name(), p)
			}
			// Anything outside the repo must be standard library, which has no
			// dot in its first path element.
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
				t.Errorf("%s imports third-party package %q; this package is stdlib-only", e.Name(), p)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no Go files found; the test would pass vacuously")
	}
}
