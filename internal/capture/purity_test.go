package capture

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbidden names every import that could put bytes on a USB bus.
var forbidden = []string{
	"goodix5120/internal/transport",
	"github.com/google/gousb",
}

// allowedRepoImports is the only intra-repository import this package may have.
// internal/proto is itself stdlib-only, which TestProtoIsStdlibOnly asserts, so
// admitting it keeps the restriction transitively airtight.
var allowedRepoImports = map[string]bool{
	"goodix5120/internal/proto": true,
}

// TestCaptureCannotReachHardware reads this package's own source and asserts
// its imports cannot reach a USB device.
//
// The point is structural. A capture tool that can only read a file cannot
// wedge the embedded controller, and after Runs 1, 2 and 4 that has to be a
// property of the code rather than of anyone's intention.
func TestCaptureCannotReachHardware(t *testing.T) {
	assertImportsAreClean(t, ".")
}

// TestProtoIsStdlibOnly backs the exemption above.
func TestProtoIsStdlibOnly(t *testing.T) {
	assertImportsAreClean(t, filepath.Join("..", "proto"))
}

func assertImportsAreClean(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		checked++

		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import %s", path, imp.Path.Value)
			}
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports %q, which can talk to hardware", path, p)
				}
			}
			if strings.HasPrefix(p, "goodix5120/") && !allowedRepoImports[p] {
				t.Errorf("%s imports %q; this package may import only %v from the repo",
					path, p, keys(allowedRepoImports))
			}
			// Anything outside the repo must be standard library, which has no
			// dot in its first path element.
			if !strings.HasPrefix(p, "goodix5120/") {
				if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
					t.Errorf("%s imports third-party package %q; this package is stdlib-only", path, p)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatalf("no Go files found in %s; the test would pass vacuously", dir)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
