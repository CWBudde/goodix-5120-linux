// Command goodix-dpapi unseals a machine-scoped DPAPI blob offline.
// It reads existing files, opens no device, and never prints keys, identifiers,
// descriptions, or plaintext hashes by default. Plaintext is emitted only with
// -out or -print-psk. See docs/dpapi-runbook.md.
package main

import "os"

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr, defaultDependencies()))
}

func run(sysPath, secPath, blobPath, mkPath, mkDir, entropyHex string, goodix bool, out string, printPSK bool) error {
	return execute(options{sysPath: sysPath, secPath: secPath, blobPath: blobPath,
		mkPath: mkPath, mkDir: mkDir, entropyHex: entropyHex, goodix: goodix,
		out: out, printPSK: printPSK}, os.Stdout, defaultDependencies())
}
