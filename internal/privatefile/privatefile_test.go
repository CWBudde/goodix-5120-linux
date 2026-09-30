package privatefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWritePrivateReplacement(t *testing.T) {
	for _, kind := range []string{"new", "existing", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secret")
			target := filepath.Join(dir, "original")
			if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "existing":
				if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := Write(path, []byte("private"), nil); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "private" {
				t.Fatalf("output = %q, %v", got, err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("output mode = %v", info.Mode())
			}
			got, err = os.ReadFile(target)
			if err != nil || string(got) != "old" {
				t.Fatalf("linked target changed: %q, %v", got, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("temporary file left behind: %v, %v", entries, err)
			}
		})
	}
}

type failingFile struct {
	*os.File
	stage   string
	failure error
}

func (f *failingFile) Chmod(mode os.FileMode) error {
	if f.stage == "chmod" {
		return f.failure
	}
	return f.File.Chmod(mode)
}
func (f *failingFile) Chown(uid, gid int) error {
	if f.stage == "chown" {
		return f.failure
	}
	return f.File.Chown(uid, gid)
}
func (f *failingFile) Write(data []byte) (int, error) {
	if f.stage == "write" {
		_, _ = f.File.Write(data[:1])
		return 1, f.failure
	}
	if f.stage == "short write" {
		return f.File.Write(data[:1])
	}
	return f.File.Write(data)
}
func (f *failingFile) Sync() error {
	if f.stage == "sync" {
		return f.failure
	}
	return f.File.Sync()
}
func (f *failingFile) Close() error {
	err := f.File.Close()
	if f.stage == "close" {
		return f.failure
	}
	return err
}

func TestWriteFailureKeepsOriginalAndCleansTemporary(t *testing.T) {
	for _, stage := range []string{"create", "chmod", "chown", "write", "short write", "sync", "close", "rename"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secret")
			if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("synthetic failure")
			ops := operations{
				createTemp: func(dir, pattern string) (temporaryFile, error) {
					if stage == "create" {
						return nil, failure
					}
					file, err := os.CreateTemp(dir, pattern)
					if err != nil {
						return nil, err
					}
					return &failingFile{file, stage, failure}, nil
				},
				rename: func(from, to string) error {
					if stage == "rename" {
						return failure
					}
					return os.Rename(from, to)
				},
				remove: os.Remove,
			}
			err := writeWithOperations(path, []byte("private"), &Ownership{os.Geteuid(), os.Getegid()}, ops)
			wantErr := failure
			if stage == "short write" {
				wantErr = io.ErrShortWrite
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v; want %v", err, wantErr)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "original" {
				t.Fatalf("original changed: %q, %v", got, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary file left behind: %v, %v", entries, err)
			}
		})
	}
}

func TestWriteOwnershipBeforePublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	ownership := &Ownership{os.Geteuid(), os.Getegid()}
	ops := operations{
		createTemp: func(dir, pattern string) (temporaryFile, error) { return os.CreateTemp(dir, pattern) },
		rename: func(from, to string) error {
			info, err := os.Stat(from)
			if err != nil {
				return err
			}
			stat := info.Sys().(*syscall.Stat_t)
			if int(stat.Uid) != ownership.UID || int(stat.Gid) != ownership.GID || info.Mode().Perm() != 0o600 {
				t.Fatalf("unprepared file at rename: %v", info)
			}
			return os.Rename(from, to)
		},
		remove: os.Remove,
	}
	if err := writeWithOperations(path, []byte("private"), ownership, ops); err != nil {
		t.Fatal(err)
	}
}

func TestWriteReportsCleanupFailure(t *testing.T) {
	dir := t.TempDir()
	failure := errors.New("synthetic rename failure")
	cleanup := errors.New("synthetic cleanup failure")
	ops := operations{
		createTemp: func(dir, pattern string) (temporaryFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     func(from, to string) error { return failure },
		remove:     func(path string) error { _ = os.Remove(path); return cleanup },
	}
	err := writeWithOperations(filepath.Join(dir, "secret"), []byte("private"), nil, ops)
	if !errors.Is(err, failure) || !errors.Is(err, cleanup) {
		t.Fatalf("error lost failure: %v", err)
	}
}

type ownershipFile struct {
	*os.File
	setOwner func(int, int) error
}

func (f *ownershipFile) Chown(uid, gid int) error { return f.setOwner(uid, gid) }

func TestWriteUsesRequestedSudoOwnership(t *testing.T) {
	// Exercise a sudo caller's requested ownership without requiring privileges
	// or changing the owner of a real test file to another account.
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	ownership := &Ownership{UID: 12345, GID: 23456}
	ownerSet := false
	ops := operations{
		createTemp: func(dir, pattern string) (temporaryFile, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			return &ownershipFile{file, func(uid, gid int) error {
				if uid != 12345 || gid != 23456 {
					t.Fatalf("wrong requested owner: %d:%d", uid, gid)
				}
				ownerSet = true
				return nil
			}}, nil
		},
		rename: func(from, to string) error {
			if !ownerSet {
				t.Fatal("published before mandatory ownership assignment")
			}
			return os.Rename(from, to)
		},
		remove: os.Remove,
	}
	if err := writeWithOperations(path, []byte("private"), ownership, ops); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "private" {
		t.Fatalf("output = %q, %v", got, err)
	}
}

func TestWriteRejectsUnspecifiedOwnership(t *testing.T) {
	max := ^uint32(0)
	invalid := []*Ownership{{UID: -1, GID: 0}, {UID: 0, GID: -1}, {UID: int(max), GID: os.Getgid()}, {UID: os.Getuid(), GID: int(max)}}
	if uint64(int(max)) == uint64(max) {
		invalid = append(invalid, &Ownership{UID: int(max) + 1, GID: 0})
	}
	for _, ownership := range invalid {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Write(path, []byte("private"), ownership); err == nil {
			t.Fatal("invalid ownership accepted")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "original" {
			t.Fatalf("original changed: %q, %v", got, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("temporary file left behind: %v, %v", entries, err)
		}
	}
}
