package dpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"goodix5120/internal/winreg"
)

// Flags for the optional live check against a real Windows mount. Without them
// the integration test skips, so `go test ./...` stays offline and secret-free.
var (
	hiveSys = flag.String("dpapi-sys", "", "SYSTEM hive path for the integration test")
	hiveSec = flag.String("dpapi-sec", "", "SECURITY hive path for the integration test")
	mkDir   = flag.String("dpapi-mkdir", "", "S-1-5-18 Protect dir for the integration test")
)

func TestBootKeyPermutation(t *testing.T) {
	// class names encode scrambled bytes 0x00..0x0f; the boot key is then the
	// permutation applied, so the result equals the permutation table itself.
	bk, err := BootKey("00010203", "04050607", "08090a0b", "0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x08, 0x05, 0x04, 0x02, 0x0b, 0x09, 0x0d, 0x03, 0x00, 0x06, 0x01, 0x0c, 0x0e, 0x0a, 0x0f, 0x07}
	if !bytes.Equal(bk, want) {
		t.Fatalf("boot key = %x, want %x", bk, want)
	}
}

func TestBootKeyRejectsNonHex(t *testing.T) {
	if _, err := BootKey("zzzzzzzz", "04050607", "08090a0b", "0c0d0e0f"); err == nil {
		t.Fatal("expected error for non-hex class name")
	}
}

func TestGoodixEntropy(t *testing.T) {
	// K is folded from the three gfusb.dll .data constants; it is a vendor
	// constant, not machine data. A synthetic seed exercises the derivation
	// structurally, without embedding any real machine secret.
	k := goodixEntropyKey()
	if got := hex.EncodeToString(k[:]); got != "04e0b0f3f5598417dde298e467c795f7" {
		t.Fatalf("folded key K = %s", got)
	}
	seed := []byte{0, 1, 2, 3, 4, 5, 6, 7} // arbitrary, not a real seed
	ent := GoodixCacheEntropy(seed)
	if len(ent) != 48 {
		t.Fatalf("entropy length = %d, want 48", len(ent))
	}
	root := sha256.Sum256(seed)
	if !bytes.Equal(ent[:16], root[16:32]) {
		t.Fatal("entropy[:16] should be SHA256(seed)[16:32]")
	}
	h := sha256.Sum256(append(append([]byte(nil), root[:16]...), k[:]...))
	if !bytes.Equal(ent[16:], h[:]) {
		t.Fatal("entropy[16:] should be SHA256(SHA256(seed)[:16] || K)")
	}
}

func TestGUIDString(t *testing.T) {
	// The master-key GUID bytes from Goodix_Cache.bin, mixed-endian.
	raw, _ := hex.DecodeString("c3a67d553d0ddf4f8834befbc7331dd6")
	if got := guidString(raw); got != "557da6c3-0d3d-4fdf-8834-befbc7331dd6" {
		t.Fatalf("guidString = %s", got)
	}
}

func TestDecodeUTF16(t *testing.T) {
	// "Hi" in UTF-16LE, with a trailing NUL that must be trimmed.
	got := decodeUTF16([]byte{'H', 0, 'i', 0, 0, 0})
	if got != "Hi" {
		t.Fatalf("decodeUTF16 = %q", got)
	}
}

func TestPKCS7Unpad(t *testing.T) {
	if out, err := pkcs7Unpad([]byte{'a', 'b', 3, 3, 3}, 16); err != nil || string(out) != "ab" {
		t.Fatalf("valid pad: out=%q err=%v", out, err)
	}
	if _, err := pkcs7Unpad([]byte{'a', 'b', 3, 2, 3}, 16); err == nil {
		t.Fatal("expected error for inconsistent padding")
	}
	if _, err := pkcs7Unpad([]byte{'a', 'b', 0}, 16); err == nil {
		t.Fatal("expected error for zero pad")
	}
}

// TestLiveMasterKeys walks a real S-1-5-18 Protect directory and asserts every
// SHA-512/AES-256 master key verifies with the machine or user DPAPI_SYSTEM
// key. It runs only when the -dpapi-* flags point at a mounted Windows volume;
// it reads nothing into the repository and prints no secrets.
func TestLiveMasterKeys(t *testing.T) {
	if *hiveSys == "" || *hiveSec == "" || *mkDir == "" {
		t.Skip("set -dpapi-sys, -dpapi-sec and -dpapi-mkdir to run")
	}
	sys, err := winreg.Open(*hiveSys)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := winreg.Open(*hiveSec)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := sys.DWord(`Select`, "Current")
	if err != nil {
		t.Fatal(err)
	}
	cs := fmt.Sprintf(`ControlSet%03d`, cur)
	cn := func(k string) string {
		s, err := sys.ClassName(cs + `\Control\Lsa\` + k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	bk, err := BootKey(cn("JD"), cn("Skew1"), cn("GBG"), cn("Data"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := sec.Binary(`Policy\PolEKList`)
	if err != nil {
		t.Fatal(err)
	}
	lsa, err := LSAKey(bk, pol)
	if err != nil {
		t.Fatal(err)
	}
	currVal, err := sec.Binary(`Policy\Secrets\DPAPI_SYSTEM\CurrVal`)
	if err != nil {
		t.Fatal(err)
	}
	dp, err := DecryptDPAPISystem(lsa, currVal)
	if err != nil {
		t.Fatal(err)
	}

	ents, err := os.ReadDir(*mkDir)
	if err != nil {
		t.Fatal(err)
	}
	var checked, verified int
	for _, e := range ents {
		if e.IsDir() || len(e.Name()) != 36 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(*mkDir, e.Name()))
		if err != nil {
			continue
		}
		mk, err := parseMasterKeyBlob(b)
		if err != nil || mk.hashAlgo != calgSHA512 || mk.cryptAlgo != calgAES256 {
			continue
		}
		checked++
		_, okM, _ := MasterKey(b, dp.Machine)
		_, okU, _ := MasterKey(b, dp.User)
		if okM || okU {
			verified++
		}
	}
	if checked == 0 {
		t.Skip("no SHA-512/AES-256 master keys found")
	}
	t.Logf("verified %d/%d master keys", verified, checked)
	if verified != checked {
		t.Fatalf("only %d of %d master keys verified", verified, checked)
	}
}
