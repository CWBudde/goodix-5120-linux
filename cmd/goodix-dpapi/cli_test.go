package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goodix5120/internal/privatefile"
)

var syntheticPlain = []byte("synthetic-psk-secret-for-cli-test")

func requiredArgs() []string {
	return []string{"-sys", "/private/SYSTEM", "-sec", "/private/SECURITY", "-blob", "/private/cache", "-mkdir", "/private/masterkeys"}
}

func assertNoSecrets(t *testing.T, output string) {
	t.Helper()
	sum := sha256.Sum256(syntheticPlain)
	for _, secret := range []string{
		string(syntheticPlain), hex.EncodeToString(syntheticPlain), hex.EncodeToString(sum[:]),
		"12345678-abcd-4321-9876-123456789abc", "synthetic-boot-key", "private-description", "/private/",
	} {
		if strings.Contains(output, secret) {
			t.Errorf("output disclosed %q: %s", secret, output)
		}
	}
}

func TestRunSanitizesMissingBlobPath(t *testing.T) {
	dir := t.TempDir()
	err := run("unused", "unused", filepath.Join(dir, "12345678-abcd-4321-9876-123456789abc"), "unused", "", "", false, "", false)
	if err == nil {
		t.Fatal("missing blob succeeded")
	}
	if strings.Contains(err.Error(), "12345678-abcd-4321-9876-123456789abc") || strings.Contains(err.Error(), dir) {
		t.Fatalf("error disclosed private input path: %v", err)
	}
}

func TestCLIDefaultWithholdsPlaintextAndMetadata(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := dependencies{recover: func(options) ([]byte, error) { return syntheticPlain, nil }, write: privatefile.Write}
	if code := runCLI(requiredArgs(), &stdout, &stderr, deps); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "33 bytes") || !strings.Contains(stdout.String(), "HMAC verified") {
		t.Fatalf("missing safe status: %s", stdout.String())
	}
	assertNoSecrets(t, stdout.String()+stderr.String())
}

func TestCLIPrintPSKIsExplicit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := dependencies{recover: func(options) ([]byte, error) { return syntheticPlain, nil }, write: privatefile.Write}
	args := append(requiredArgs(), "-print-psk")
	if code := runCLI(args, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), hex.EncodeToString(syntheticPlain)) {
		t.Fatalf("explicit plaintext absent: %s", stdout.String())
	}
	sum := sha256.Sum256(syntheticPlain)
	if strings.Contains(stdout.String(), hex.EncodeToString(sum[:])) {
		t.Fatal("print option leaked plaintext hash")
	}
}

func TestCLIPrivateOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := dependencies{recover: func(options) ([]byte, error) { return syntheticPlain, nil }, write: privatefile.Write}
	if code := runCLI(append(requiredArgs(), "-out", path), &stdout, &stderr, deps); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, syntheticPlain) {
		t.Fatalf("private output = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private mode = %v", info.Mode())
	}
	assertNoSecrets(t, stdout.String()+stderr.String())
}

func TestCLIFailuresAreSanitized(t *testing.T) {
	for _, stage := range []string{"recovery", "publication"} {
		t.Run(stage, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			failure := errors.New("/private/12345678-abcd-4321-9876-123456789abc synthetic-boot-key private-description " + hex.EncodeToString(syntheticPlain))
			deps := dependencies{
				recover: func(options) ([]byte, error) {
					if stage == "recovery" {
						return nil, failure
					}
					return syntheticPlain, nil
				},
				write: func(string, []byte, *privatefile.Ownership) error { return failure },
			}
			if code := runCLI(append(requiredArgs(), "-out", "/private/output", "-print-psk"), &stdout, &stderr, deps); code != 1 {
				t.Fatalf("exit = %d", code)
			}
			if !strings.Contains(stderr.String(), "error:") {
				t.Fatalf("missing safe error: %s", stderr.String())
			}
			assertNoSecrets(t, stdout.String()+stderr.String())
		})
	}
}

func TestCLIInvalidArgumentsDoNotRecoverOrDisclose(t *testing.T) {
	for _, args := range [][]string{nil, append(requiredArgs(), "-unknown-/private/secret"), append(requiredArgs(), "-goodix", "-entropy", "00")} {
		var stdout, stderr bytes.Buffer
		deps := dependencies{recover: func(options) ([]byte, error) { t.Fatal("recovery attempted for invalid arguments"); return nil, nil }}
		if code := runCLI(args, &stdout, &stderr, deps); code != 2 {
			t.Fatalf("exit = %d", code)
		}
		assertNoSecrets(t, stdout.String()+stderr.String())
	}
}
