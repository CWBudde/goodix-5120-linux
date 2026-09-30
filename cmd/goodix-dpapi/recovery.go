package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"goodix5120/internal/dpapi"
	"goodix5120/internal/winreg"
)

// recoveryError exposes only a fixed stage label. Input paths, GUIDs, and parser
// details stay in the cause for errors.Is/As and never enter CLI output.
type recoveryError struct {
	stage string
	cause error
}

func (e *recoveryError) Error() string                { return e.stage }
func (e *recoveryError) Unwrap() error                { return e.cause }
func recoveryFailure(stage string, cause error) error { return &recoveryError{stage, cause} }

func recoverPlaintext(opts options) ([]byte, error) {
	// 1. Parse the blob first, so we know which master key to use.
	blobBytes, err := os.ReadFile(opts.blobPath)
	if err != nil {
		return nil, recoveryFailure("cannot read DPAPI blob", err)
	}
	blob, err := dpapi.ParseBlob(blobBytes)
	if err != nil {
		return nil, recoveryFailure("invalid DPAPI blob", err)
	}

	var entropy []byte
	if opts.entropyHex != "" {
		entropy, err = hex.DecodeString(strings.TrimSpace(opts.entropyHex))
		if err != nil {
			return nil, recoveryFailure("invalid -entropy hex", err)
		}
	}
	if opts.goodix {
		if entropy != nil {
			return nil, recoveryFailure("use either -goodix or -entropy, not both", nil)
		}
		seed := blobBytes[blob.SealedLen:]
		if len(seed) != 8 {
			return nil, recoveryFailure("-goodix requires exactly 8 trailing seed bytes", nil)
		}
		entropy = dpapi.GoodixCacheEntropy(seed)
	}

	// 2. Boot key from the SYSTEM hive.
	sys, err := winreg.Open(opts.sysPath)
	if err != nil {
		return nil, recoveryFailure("cannot read SYSTEM hive", err)
	}
	current, err := sys.DWord(`Select`, "Current")
	if err != nil {
		return nil, recoveryFailure("cannot read current control set", err)
	}
	cs := fmt.Sprintf("ControlSet%03d", current)
	names := make([]string, 4)
	for i, k := range []string{"JD", "Skew1", "GBG", "Data"} {
		cn, err := sys.ClassName(cs + `\Control\Lsa\` + k)
		if err != nil {
			return nil, recoveryFailure("cannot read LSA class name", err)
		}
		names[i] = cn
	}
	bootKey, err := dpapi.BootKey(names[0], names[1], names[2], names[3])
	if err != nil {
		return nil, recoveryFailure("cannot derive boot key", err)
	}

	// 3. LSA key and DPAPI_SYSTEM secret from the SECURITY hive.
	sec, err := winreg.Open(opts.secPath)
	if err != nil {
		return nil, recoveryFailure("cannot read SECURITY hive", err)
	}
	polEKList, err := sec.Binary(`Policy\PolEKList`)
	if err != nil {
		return nil, recoveryFailure("cannot read LSA policy key", err)
	}
	lsaKey, err := dpapi.LSAKey(bootKey, polEKList)
	if err != nil {
		return nil, recoveryFailure("cannot recover LSA key", err)
	}
	currVal, err := sec.Binary(`Policy\Secrets\DPAPI_SYSTEM\CurrVal`)
	if err != nil {
		return nil, recoveryFailure("cannot read DPAPI_SYSTEM secret", err)
	}
	sysKeys, err := dpapi.DecryptDPAPISystem(lsaKey, currVal)
	if err != nil {
		return nil, recoveryFailure("cannot recover DPAPI_SYSTEM keys", err)
	}

	// 4. Locate and decrypt the master key.
	mkPath := opts.mkPath
	if mkPath == "" {
		mkPath = filepath.Join(opts.mkDir, blob.MasterKeyGUID)
		if _, err := os.Stat(mkPath); err != nil {
			return nil, recoveryFailure("cannot locate matching master-key file", err)
		}
	}
	mkBytes, err := os.ReadFile(mkPath)
	if err != nil {
		return nil, recoveryFailure("cannot read master-key file", err)
	}
	masterKey, _, err := decryptMasterKey(mkBytes, sysKeys)
	if err != nil {
		return nil, recoveryFailure("cannot decrypt master-key file", err)
	}

	// 5. Decrypt the blob (also HMAC-verified).
	plain, err := blob.Decrypt(masterKey, entropy)
	if errors.Is(err, dpapi.ErrHMAC) && len(entropy) == 0 {
		return nil, recoveryFailure("DPAPI blob HMAC verification failed; application entropy may be required (-goodix or -entropy)", err)
	}
	if err != nil {
		return nil, recoveryFailure("cannot decrypt DPAPI blob", err)
	}
	return plain, nil
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
