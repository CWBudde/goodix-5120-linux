package tlspsk

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"testing"
)

func TestReferencePSK(t *testing.T) {
	psk := ReferencePSK()
	if len(psk) != 32 {
		t.Fatalf("ReferencePSK length = %d, want 32", len(psk))
	}
	for i, b := range psk {
		if b != 0 {
			t.Fatalf("ReferencePSK[%d] = 0x%02x, want 0x00", i, b)
		}
	}
	if hex.EncodeToString(psk) != ReferencePSKHex {
		t.Fatal("ReferencePSK does not round-trip ReferencePSKHex")
	}
	// Mutating the returned slice must not affect later callers.
	psk[0] = 0xff
	if ReferencePSK()[0] != 0x00 {
		t.Fatal("ReferencePSK returns shared state")
	}
}

func TestLoadPSK(t *testing.T) {
	dir := t.TempDir()

	// A well-formed 32-byte raw key round-trips. These bytes are a throwaway
	// test fixture, not a real device secret.
	want := make([]byte, PSKLen)
	for i := range want {
		want[i] = byte(i)
	}
	good := dir + "/psk.bin"
	if err := os.WriteFile(good, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPSK(good)
	if err != nil {
		t.Fatalf("LoadPSK: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("LoadPSK = %x, want %x", got, want)
	}

	// Wrong length is an error, not a truncation. A 64-byte hex dump of a
	// 32-byte key is the likely mistake, so check that shape specifically.
	hexDump := dir + "/psk.hex"
	if err := os.WriteFile(hexDump, []byte(hex.EncodeToString(want)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPSK(hexDump); err == nil {
		t.Fatal("LoadPSK accepted a 64-byte hex file as a raw key")
	}

	short := dir + "/short.bin"
	if err := os.WriteFile(short, want[:16], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPSK(short); err == nil {
		t.Fatal("LoadPSK accepted a 16-byte file")
	}

	if _, err := LoadPSK(dir + "/does-not-exist.bin"); err == nil {
		t.Fatal("LoadPSK accepted a missing file")
	}
}

func TestParsePSKHex(t *testing.T) {
	// ReferencePSKHex is the canonical 32-byte hex form; it must parse and match.
	got, err := ParsePSKHex(ReferencePSKHex)
	if err != nil {
		t.Fatalf("ParsePSKHex(ReferencePSKHex): %v", err)
	}
	if !bytes.Equal(got, ReferencePSK()) {
		t.Fatal("ParsePSKHex(ReferencePSKHex) != ReferencePSK()")
	}

	// Surrounding whitespace (e.g. a trailing newline from a shell) is tolerated.
	if _, err := ParsePSKHex("\t" + ReferencePSKHex + "\n"); err != nil {
		t.Fatalf("ParsePSKHex should trim whitespace: %v", err)
	}

	if _, err := ParsePSKHex("zz"); err == nil {
		t.Fatal("ParsePSKHex accepted non-hex")
	}
	if _, err := ParsePSKHex("00112233"); err == nil {
		t.Fatal("ParsePSKHex accepted a short key")
	}
}

func TestNativeStartDoesNotRequireExecutable(t *testing.T) {
	t.Setenv("PATH", "")
	s, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatalf("native endpoint requires executable: %v", err)
	}
	defer s.Close()
}
func TestStartRequiresExactly32BytePSK(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		s, err := Start(context.Background(), Config{PSK: make([]byte, n)})
		if s != nil {
			s.Close()
		}
		if err == nil {
			t.Errorf("accepted %d-byte PSK", n)
		}
	}
}
