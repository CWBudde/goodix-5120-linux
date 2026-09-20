// Command goodix-dpapi unseals a machine-scoped DPAPI blob offline.
//
// It is the Phase 5 (option 1) tool: it recovers the Goodix TLS-PSK from
// Goodix_Cache.bin using only files already on the machine — the SYSTEM and
// SECURITY registry hives and the LocalSystem master-key file — with no
// password and no brute force. It reads those files, opens no device, and
// touches no hardware. Windows Hello is unaffected. See PLAN.md Phase 5 and
// docs/dpapi-runbook.md.
//
// The recovered PSK is a secret, handled the way this repository handles the
// OTP and the 0xe4 reply: by default it is NOT printed. The tool prints the
// plaintext length and its SHA-256 so a run can be confirmed, writes the raw
// bytes only to a file named with -out, and prints the hex only with
// -print-psk. Keep any -out file out of the repository (captures/ is
// gitignored).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"goodix5120/internal/dpapi"
	"goodix5120/internal/winreg"
)

func main() {
	var (
		sysPath  = flag.String("sys", "", "path to the SYSTEM registry hive (required)")
		secPath  = flag.String("sec", "", "path to the SECURITY registry hive (required)")
		blobPath = flag.String("blob", "", "path to the sealed DPAPI blob, e.g. Goodix_Cache.bin (required)")
		mkPath   = flag.String("mk", "", "path to the master-key file matching the blob's GUID")
		mkDir    = flag.String("mkdir", "", "directory of master-key files; the one matching the blob's GUID is chosen (alternative to -mk)")
		entropy  = flag.String("entropy", "", "optional secondary entropy, as hex")
		out      = flag.String("out", "", "write the recovered plaintext (raw bytes) to this file; keep it out of the repo")
		printPSK = flag.Bool("print-psk", false, "print the recovered plaintext in hex to stdout (a secret; off by default)")
	)
	flag.Parse()

	if *sysPath == "" || *secPath == "" || *blobPath == "" || (*mkPath == "" && *mkDir == "") {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*sysPath, *secPath, *blobPath, *mkPath, *mkDir, *entropy, *out, *printPSK); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(sysPath, secPath, blobPath, mkPath, mkDir, entropyHex, out string, printPSK bool) error {
	// 1. Parse the blob first, so we know which master key to use.
	blobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		return err
	}
	blob, err := dpapi.ParseBlob(blobBytes)
	if err != nil {
		return err
	}
	fmt.Printf("blob:       %s\n", blobPath)
	fmt.Printf("  master key GUID: %s\n", blob.MasterKeyGUID)
	if blob.Description != "" {
		fmt.Printf("  description:     %q\n", blob.Description)
	}

	var entropy []byte
	if entropyHex != "" {
		entropy, err = hex.DecodeString(strings.TrimSpace(entropyHex))
		if err != nil {
			return fmt.Errorf("bad -entropy hex: %w", err)
		}
	}

	// 2. Boot key from the SYSTEM hive.
	sys, err := winreg.Open(sysPath)
	if err != nil {
		return err
	}
	current, err := sys.DWord(`Select`, "Current")
	if err != nil {
		return fmt.Errorf("reading Select\\Current: %w", err)
	}
	cs := fmt.Sprintf("ControlSet%03d", current)
	names := make([]string, 4)
	for i, k := range []string{"JD", "Skew1", "GBG", "Data"} {
		cn, err := sys.ClassName(cs + `\Control\Lsa\` + k)
		if err != nil {
			return fmt.Errorf("reading LSA class name %s: %w", k, err)
		}
		names[i] = cn
	}
	bootKey, err := dpapi.BootKey(names[0], names[1], names[2], names[3])
	if err != nil {
		return err
	}
	fmt.Printf("boot key:   %s (from %s)\n", hex.EncodeToString(bootKey), cs)

	// 3. LSA key and DPAPI_SYSTEM secret from the SECURITY hive.
	sec, err := winreg.Open(secPath)
	if err != nil {
		return err
	}
	polEKList, err := sec.Binary(`Policy\PolEKList`)
	if err != nil {
		return fmt.Errorf("reading PolEKList: %w", err)
	}
	lsaKey, err := dpapi.LSAKey(bootKey, polEKList)
	if err != nil {
		return err
	}
	currVal, err := sec.Binary(`Policy\Secrets\DPAPI_SYSTEM\CurrVal`)
	if err != nil {
		return fmt.Errorf("reading DPAPI_SYSTEM: %w", err)
	}
	sysKeys, err := dpapi.DecryptDPAPISystem(lsaKey, currVal)
	if err != nil {
		return err
	}
	fmt.Println("dpapi:      DPAPI_SYSTEM machine and user keys recovered")

	// 4. Locate and decrypt the master key.
	if mkPath == "" {
		mkPath = filepath.Join(mkDir, blob.MasterKeyGUID)
		if _, err := os.Stat(mkPath); err != nil {
			return fmt.Errorf("no master-key file %s in %s: %w", blob.MasterKeyGUID, mkDir, err)
		}
	}
	mkBytes, err := os.ReadFile(mkPath)
	if err != nil {
		return err
	}
	masterKey, which, err := decryptMasterKey(mkBytes, sysKeys)
	if err != nil {
		return err
	}
	fmt.Printf("master key: recovered and HMAC-verified (%s key)\n", which)

	// 5. Decrypt the blob (also HMAC-verified).
	plain, err := blob.Decrypt(masterKey, entropy)
	if errors.Is(err, dpapi.ErrHMAC) && len(entropy) == 0 {
		return fmt.Errorf("%w\n"+
			"the master key is verified and the blob is well-formed, so this blob was sealed\n"+
			"with application-specific secondary entropy. Supply it with -entropy HEX.", err)
	}
	if err != nil {
		return err
	}

	sum := sha256.Sum256(plain)
	fmt.Println("---")
	fmt.Printf("plaintext:  %d bytes, sha256 %s  [HMAC verified]\n", len(plain), hex.EncodeToString(sum[:]))

	if out != "" {
		if err := os.WriteFile(out, plain, 0o600); err != nil {
			return err
		}
		fmt.Printf("written to: %s (keep this out of the repository)\n", out)
	}
	if printPSK {
		fmt.Printf("PSK (hex):  %s\n", hex.EncodeToString(plain))
	}
	if out == "" && !printPSK {
		fmt.Println("(plaintext withheld; use -out FILE or -print-psk to emit it)")
	}
	return nil
}

func decryptMasterKey(mkBytes []byte, sysKeys *dpapi.DPAPISystem) (key []byte, which string, err error) {
	for _, cand := range []struct {
		name string
		hash []byte
	}{
		{"machine", sysKeys.Machine},
		{"user", sysKeys.User},
	} {
		k, ok, err := dpapi.MasterKey(mkBytes, cand.hash)
		if err != nil {
			return nil, "", err
		}
		if ok {
			return k, cand.name, nil
		}
	}
	return nil, "", fmt.Errorf("master-key HMAC did not verify with either DPAPI_SYSTEM key")
}
