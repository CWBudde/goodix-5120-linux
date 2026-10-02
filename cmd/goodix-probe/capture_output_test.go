package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"goodix5120/internal/image"
)

func TestCaptureReplacesPublicSymlinkWithoutFollowing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "other")
	output := filepath.Join(dir, "capture.pgm")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	if err := writeCapture(output, image.Gray8{Width: 1, Height: 1, Pix: []byte{42}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(output)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("capture mode %v", info.Mode())
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "untouched" {
		t.Fatal("symlink target overwritten")
	}
	b, err = os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "P5\n1 1\n255\n*" {
		t.Fatalf("capture %q", b)
	}
}

func TestCaptureSudoOwnershipValidation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		euid             int
		uid, gid         string
		wantUID, wantGID int
		wantErr          bool
		wantNil          bool
	}{
		{name: "ordinary user", euid: 1000, uid: "broken", gid: "broken", wantNil: true},
		{name: "direct root", euid: 0, wantNil: true},
		{name: "sudo", euid: 0, uid: "1000", gid: "1001", wantUID: 1000, wantGID: 1001},
		{name: "partial sudo", euid: 0, uid: "1000", wantErr: true},
		{name: "invalid sudo", euid: 0, uid: "no", gid: "1000", wantErr: true},
		{name: "negative sudo", euid: 0, uid: "-1", gid: "1000", wantErr: true},
		{name: "unchanged uid sentinel", euid: 0, uid: "4294967295", gid: "1000", wantErr: true},
		{name: "unchanged gid sentinel", euid: 0, uid: "1000", gid: "4294967295", wantErr: true},
		{name: "uid wraparound", euid: 0, uid: "4294967296", gid: "1000", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, err := captureOwnership(tc.euid, tc.uid, tc.gid)
			if tc.wantErr {
				if err == nil {
					t.Fatal("missing ownership error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNil {
				if owner != nil {
					t.Fatalf("unexpected owner %+v", owner)
				}
				return
			}
			if owner == nil || owner.UID != tc.wantUID || owner.GID != tc.wantGID {
				t.Fatalf("owner %+v", owner)
			}
		})
	}
}

// Owner-run offline check: sudo env GOCACHE=/tmp/goodix-owner-cache go test
// ./cmd/goodix-probe -run TestCaptureSudoOwnershipOnDisk -count=1
// This encodes one synthetic pixel and never opens a device.
func TestCaptureSudoOwnershipOnDisk(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires sudo for final capture ownership check")
	}
	owner, err := sudoOwnership()
	if err != nil {
		t.Fatal(err)
	}
	if owner == nil {
		t.Skip("requires invoking user's SUDO_UID/SUDO_GID")
	}
	path := filepath.Join(t.TempDir(), "synthetic.pgm")
	if err := writeCapture(path, image.Gray8{Width: 1, Height: 1, Pix: []byte{42}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != owner.UID || int(stat.Gid) != owner.GID || info.Mode().Perm() != 0o600 {
		t.Fatalf("published capture owner %d:%d mode %v, want %d:%d 0600", stat.Uid, stat.Gid, info.Mode(), owner.UID, owner.GID)
	}
}
