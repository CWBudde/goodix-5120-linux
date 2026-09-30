// Package privatefile publishes secret and biometric output privately.
package privatefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Ownership specifies the final file's owner when a caller is running with sudo.
type Ownership struct{ UID, GID int }

// Write atomically replaces a path with a 0600 regular file. It prepares and
// syncs a temporary file in the destination directory, applies any required
// ownership, and closes it before rename. Existing symlinks and hardlink entries
// are replaced without writing through them. Errors before rename preserve the
// original entry; failed temporary-file cleanup is included in the returned error.
func Write(path string, data []byte, ownership *Ownership) error {
	return writeWithOperations(path, data, ownership, operations{
		createTemp: func(dir, pattern string) (temporaryFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
		remove:     os.Remove,
	})
}

type temporaryFile interface {
	Name() string
	Chmod(os.FileMode) error
	Chown(int, int) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type operations struct {
	createTemp func(string, string) (temporaryFile, error)
	rename     func(string, string) error
	remove     func(string) error
}

func writeWithOperations(path string, data []byte, ownership *Ownership, ops operations) (retErr error) {
	file, err := ops.createTemp(filepath.Dir(path), ".goodix-private-*")
	if err != nil {
		return fmt.Errorf("create private output: %w", err)
	}
	closed, published := false, false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close private output: %w", err))
			}
		}
		if !published {
			if err := ops.remove(file.Name()); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("remove temporary output: %w", err))
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("set private output permissions: %w", err)
	}
	if ownership != nil {
		if ownership.UID < 0 || ownership.GID < 0 || uint64(ownership.UID) >= 1<<32-1 || uint64(ownership.GID) >= 1<<32-1 {
			return errors.New("private output ownership must specify UID and GID in 0..4294967294")
		}
		if err := file.Chown(ownership.UID, ownership.GID); err != nil {
			return fmt.Errorf("set private output ownership: %w", err)
		}
	}
	n, err := file.Write(data)
	if err != nil {
		return fmt.Errorf("write private output: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write private output: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync private output: %w", err)
	}
	err = file.Close()
	closed = true
	if err != nil {
		return fmt.Errorf("close private output: %w", err)
	}
	if err := ops.rename(file.Name(), path); err != nil {
		return fmt.Errorf("publish private output: %w", err)
	}
	published = true
	return nil
}
