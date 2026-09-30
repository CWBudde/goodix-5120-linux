package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"

	"goodix5120/internal/privatefile"
)

type options struct {
	sysPath, secPath, blobPath, mkPath, mkDir, entropyHex string
	goodix                                                bool
	out                                                   string
	printPSK                                              bool
}

type dependencies struct {
	recover func(options) ([]byte, error)
	write   func(string, []byte, *privatefile.Ownership) error
}

func runCLI(args []string, stdout, stderr io.Writer, deps dependencies) int {
	var opts options
	flags := flag.NewFlagSet("goodix-dpapi", flag.ContinueOnError)
	// Flag parsing errors can include user-supplied paths and values.
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.sysPath, "sys", "", "path to the SYSTEM registry hive (required)")
	flags.StringVar(&opts.secPath, "sec", "", "path to the SECURITY registry hive (required)")
	flags.StringVar(&opts.blobPath, "blob", "", "path to the sealed DPAPI blob (required)")
	flags.StringVar(&opts.mkPath, "mk", "", "path to the matching master-key file")
	flags.StringVar(&opts.mkDir, "mkdir", "", "directory of master-key files (alternative to -mk)")
	flags.StringVar(&opts.entropyHex, "entropy", "", "optional secondary entropy, as hex")
	flags.BoolVar(&opts.goodix, "goodix", false, "derive secondary entropy from the cache's trailing seed")
	flags.StringVar(&opts.out, "out", "", "write plaintext to a private file; keep it out of the repository")
	flags.BoolVar(&opts.printPSK, "print-psk", false, "print the recovered plaintext in hex (secret; off by default)")
	usage := func() {
		fmt.Fprintln(stderr, "Usage: goodix-dpapi -sys FILE -sec FILE -blob FILE (-mk FILE | -mkdir DIR) [options]")
		flags.SetOutput(stderr)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage()
			return 0
		}
		fmt.Fprintln(stderr, "error: invalid arguments")
		return 2
	}
	if flags.NArg() != 0 || opts.sysPath == "" || opts.secPath == "" || opts.blobPath == "" || (opts.mkPath == "" && opts.mkDir == "") {
		usage()
		return 2
	}
	if opts.goodix && opts.entropyHex != "" {
		fmt.Fprintln(stderr, "error: use either -goodix or -entropy, not both")
		return 2
	}
	if err := execute(opts, stdout, deps); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func defaultDependencies() dependencies {
	return dependencies{recover: recoverPlaintext, write: privatefile.Write}
}

func execute(opts options, stdout io.Writer, deps dependencies) error {
	plain, err := deps.recover(opts)
	if err != nil {
		var safe *recoveryError
		if errors.As(err, &safe) {
			return safe
		}
		return recoveryFailure("DPAPI recovery failed", err)
	}
	if opts.out != "" {
		if err := deps.write(opts.out, plain, nil); err != nil {
			return recoveryFailure("cannot write private plaintext output", err)
		}
	}
	if _, err := fmt.Fprintf(stdout, "plaintext: %d bytes [HMAC verified]\n", len(plain)); err != nil {
		return recoveryFailure("cannot report recovery status", err)
	}
	if opts.out != "" {
		if _, err := fmt.Fprintln(stdout, "private plaintext output written (keep it out of the repository)"); err != nil {
			return recoveryFailure("cannot report output status", err)
		}
	}
	if opts.printPSK {
		if _, err := fmt.Fprintf(stdout, "PSK (hex): %s\n", hex.EncodeToString(plain)); err != nil {
			return recoveryFailure("cannot print requested plaintext", err)
		}
	} else if opts.out == "" {
		if _, err := fmt.Fprintln(stdout, "(plaintext withheld; use -out FILE or -print-psk to emit it)"); err != nil {
			return recoveryFailure("cannot report output options", err)
		}
	}
	return nil
}
