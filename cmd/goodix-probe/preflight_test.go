package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/tlspsk"
	"goodix5120/internal/transport"
)

// TLS local failures must stop before host monitoring or USB open/init.
func TestTLSPreflightStopsBeforeHardware(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contents    []byte
		write       bool
		endpointErr error
	}{
		{name: "missing key"},
		{name: "short key", contents: []byte{1}, write: true},
		{name: "local policy", contents: make([]byte, 32), write: true, endpointErr: errors.New("policy refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "key.bin")
			if tc.write {
				if err := os.WriteFile(key, tc.contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			started := 0
			deps := bisectDependencies{
				newHost: func() bisectHost { t.Fatal("host watcher reached after TLS failure"); return nil },
				openUSB: func(transport.Options) (transport.Transport, error) {
					t.Fatal("USB opener reached after TLS failure")
					return nil, nil
				},
				startTLS: func(context.Context, tlspsk.Config) (*tlspsk.Session, error) { started++; return nil, tc.endpointErr },
			}
			allowed := map[proto.Opcode]bool{opRequestTLS: true}
			code := mainBisectWithDeps(false, false, false, []proto.Opcode{opRequestTLS}, allowed,
				tlsConfig{enabled: true, pskPath: key}, "a8", filepath.Join(dir, "run.log"), time.Second, deps)
			if code != 1 {
				t.Fatalf("exit %d, want 1", code)
			}
			want := 0
			if tc.endpointErr != nil {
				want = 1
			}
			if started != want {
				t.Fatalf("endpoint starts %d,want%d", started, want)
			}
		})
	}
}

func TestTLSReplayDoesNotRequireDeviceKey(t *testing.T) {
	allowed := map[proto.Opcode]bool{opRequestTLS: true}
	if err := (tlsConfig{enabled: true}).validate(nil, allowed, true); err != nil {
		t.Fatal(err)
	}
}

func TestReplayNeverObservesLiveHostOrOpensUSB(t *testing.T) {
	deps := bisectDependencies{
		newHost: func() bisectHost { t.Fatal("replay constructed a live host"); return nil },
		openUSB: func(transport.Options) (transport.Transport, error) { t.Fatal("replay opened USB"); return nil, nil },
		startTLS: func(context.Context, tlspsk.Config) (*tlspsk.Session, error) {
			t.Fatal("plain replay started TLS")
			return nil, nil
		},
	}
	code := mainBisectWithDeps(true, false, false, nil, nil, tlsConfig{}, "a8",
		filepath.Join(t.TempDir(), "run.log"), time.Second, deps)
	if code != 0 {
		t.Fatalf("exit %d, want successful offline replay", code)
	}
}
