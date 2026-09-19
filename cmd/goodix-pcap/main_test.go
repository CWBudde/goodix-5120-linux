package main

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"goodix5120/internal/proto"
)

// TestPcapToolCannotReachHardware asserts this command cannot talk to a device.
// It reads a file and writes to stdout; that is the whole of it, and it is
// enforced here rather than left to intent.
func TestPcapToolCannotReachHardware(t *testing.T) {
	allowed := map[string]bool{
		"goodix5120/internal/capture": true,
		"goodix5120/internal/proto":   true,
	}
	forbidden := []string{"goodix5120/internal/transport", "github.com/google/gousb"}

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
			if strings.HasPrefix(p, "goodix5120/") && !allowed[p] {
				t.Errorf("%s imports %q, which is not on this command's allowlist", e.Name(), p)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files found; the test would pass vacuously")
	}
}

// TestSecretPayloadsAreRefused pins the deny list. A capture of this device
// holds a hash of the device PSK and its OTP; no flag may print either, whatever
// the caller asks for.
func TestSecretPayloadsAreRefused(t *testing.T) {
	for _, spec := range []string{"e4", "0xE4", " a6 ", "A6"} {
		if _, err := parseShow(spec); err == nil {
			t.Errorf("parseShow(%q) was allowed; that payload carries a secret", spec)
		}
	}

	for _, spec := range []string{"ae", "32", "0x34"} {
		if _, err := parseShow(spec); err != nil {
			t.Errorf("parseShow(%q) = %v, want it allowed", spec, err)
		}
	}

	if _, err := parseShow("zz"); err == nil {
		t.Error("parseShow(\"zz\") was accepted")
	}
}

// The deny list is keyed by opcode, so it must name opcodes that exist.
func TestSecretOpcodesAreRegistered(t *testing.T) {
	for op := range secret {
		if _, ok := op.Class(); !ok {
			t.Errorf("deny list names unregistered opcode 0x%02x", byte(op))
		}
	}
	for _, op := range []proto.Opcode{0xe4, 0xa6} {
		if _, ok := secret[op]; !ok {
			t.Errorf("0x%02x (%s) is not on the deny list", byte(op), op.Name())
		}
	}
}
