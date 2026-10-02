package tlspsk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func nativePair(t *testing.T) (*Session, *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	server, err := Start(ctx, Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	client, err := StartClient(ctx, Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	go func() { _, _ = io.Copy(server.Device(), client.Device()) }()
	go func() { _, _ = io.Copy(client.Device(), server.Device()) }()
	return server, client
}

func TestNativeBidirectionalMultipleImages(t *testing.T) {
	server, client := nativePair(t)
	for i := 0; i < 3; i++ {
		image := bytes.Repeat([]byte{byte(i + 1), 0x71, 0x03}, 2560)
		if n, err := client.Write(image); err != nil || n != len(image) {
			t.Fatalf("client Write: %d %v", n, err)
		}
		got := make([]byte, len(image))
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, image) {
			t.Fatal("decrypted image differs")
		}
		reply := []byte("host response")
		if _, err := server.Write(reply); err != nil {
			t.Fatal(err)
		}
		got = make([]byte, len(reply))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, reply) {
			t.Fatal("client decrypted response differs")
		}
	}
}

func TestDeviceWriteDoesNotWaitForOutputReader(t *testing.T) {
	server, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := StartClient(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Device().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 4096)
	n, err := client.Device().Read(hello)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := server.Device().Write(hello[:n]); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Device.Write blocked waiting for generated ciphertext to be read")
	}
	if n, err := server.Device().Read(hello); err != nil || n == 0 {
		t.Fatalf("server output: %d %v", n, err)
	}
}

func TestDeviceDeadlineChangesWakeBlockedRead(t *testing.T) {
	s, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	result := make(chan error, 1)
	go func() { _, err := s.Device().Read(make([]byte, 1)); result <- err }()
	if err := s.Device().SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read ignored new deadline")
	}
	if err := s.Device().SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Device().Write([]byte{1}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write deadline: %v", err)
	}
	if err := s.Device().SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationAndConcurrentCloseWakeReadersAndPlaintextWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 3)
	go func() { _, err := s.Read(make([]byte, 1)); done <- err }()
	go func() { _, err := s.Device().Read(make([]byte, 1)); done <- err }()
	go func() { _, err := s.Write([]byte("pending handshake")); done <- err }()
	cancel()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	wg.Wait()
	for i := 0; i < 3; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blocked operation succeeded after cancellation")
			}
		case <-time.After(time.Second):
			t.Fatal("blocked operation not released")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native != nil || len(s.plain) > 0 || len(s.cipher) > 0 {
		t.Fatal("closed endpoint retains native state or queued data")
	}
}

func TestInputQueueOverflowIsFatal(t *testing.T) {
	s, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Device().Write(make([]byte, 65537)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("oversized input: %v", err)
	}
	if _, err := s.Device().Read(make([]byte, 1)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow did not terminate endpoint: %v", err)
	}
}

func TestOpenSSLSystemPolicyLevels(t *testing.T) {
	// Each subprocess initializes OpenSSL under a fresh system configuration.
	// Production has no security-level setter or compatibility override.
	if os.Getenv("GOODIX_POLICY_CHILD") == "1" {
		err := Preflight(context.Background())
		if os.Getenv("GOODIX_POLICY_ACCEPT") == "1" {
			if err != nil {
				t.Fatalf("permitted device suite rejected: %v", err)
			}
			s, err := Start(context.Background(), Config{PSK: ReferencePSK()})
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
		} else {
			if !errors.Is(err, ErrPolicy) {
				t.Fatalf("policy refusal classification: %v", err)
			}
			if s, err := Start(context.Background(), Config{PSK: ReferencePSK()}); !errors.Is(err, ErrPolicy) {
				if s != nil {
					s.Close()
				}
				t.Fatalf("Start bypassed policy: %v", err)
			}
		}
		return
	}
	for _, level := range []string{"0", "1", "2", "3", "4", "5"} {
		t.Run(level, func(t *testing.T) {
			conf := filepath.Join(t.TempDir(), "openssl.cnf")
			content := "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = policy\n[policy]\nCipherString = DEFAULT:@SECLEVEL=" + level + "\n"
			if err := os.WriteFile(conf, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOpenSSLSystemPolicyLevels$", "-test.count=1")
			accept := "0"
			if level <= "2" {
				accept = "1"
			}
			cmd.Env = append(os.Environ(), "OPENSSL_CONF="+conf, "GOODIX_POLICY_CHILD=1", "GOODIX_POLICY_ACCEPT="+accept)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("security level %s: %v\n%s", level, err, out)
			}
		})
	}
}

// quietPair completes the real handshake synchronously, then leaves both output
// queues undrained so that queue exhaustion can be tested without a relay race.
func quietPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	server, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	client, err := StartClient(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	for turn := 0; turn < 8; turn++ {
		for _, pair := range [][2]*Session{{client, server}, {server, client}} {
			source, dest := pair[0], pair[1]
			if err := source.Device().SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			for {
				buf := make([]byte, 65536)
				n, err := source.Device().Read(buf)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := dest.Device().Write(buf[:n]); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.Device().SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		if server.ready && client.ready {
			return server, client
		}
	}
	t.Fatal("native handshake did not settle")
	return nil, nil
}

func TestCiphertextQueueOverflowIsFatal(t *testing.T) {
	_, client := quietPair(t)
	_, err := client.Write(make([]byte, 65536))
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("undrained ciphertext did not fail bounded: %v", err)
	}
	if _, err := client.Device().Read(make([]byte, 1)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow retained output or wrong error: %v", err)
	}
}

func TestPlaintextQueueOverflowIsFatal(t *testing.T) {
	server, client := quietPair(t)
	for i := 0; i < 5; i++ {
		if _, err := client.Write(make([]byte, 16384)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 20000)
		n, err := client.Device().Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		_, err = server.Device().Write(buf[:n])
		if i < 4 && err != nil {
			t.Fatalf("premature plaintext overflow on record%d: %v", i, err)
		}
		if i == 4 && !errors.Is(err, ErrOverflow) {
			t.Fatalf("fifth 16KiB plaintext record: %v", err)
		}
	}
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("overflow retained plaintext or wrong error: %v", err)
	}
}

func TestCallerCanClearPSKAfterNativeCopy(t *testing.T) {
	key := ReferencePSK()
	server, err := Start(context.Background(), Config{PSK: key})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for i := range key {
		key[i] = 0xff
	}
	client, err := StartClient(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	go func() { _, _ = io.Copy(server.Device(), client.Device()) }()
	go func() { _, _ = io.Copy(client.Device(), server.Device()) }()
	done := make(chan error, 1)
	go func() { _, err := client.Write([]byte("independent key ownership")); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("native retained caller key: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake failed after caller key changed")
	}
	got := make([]byte, 25)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "independent key ownership" {
		t.Fatalf("wrong decrypted data: %q", got)
	}
}

func TestNativeEndpointOpensNoSocketsOrChildren(t *testing.T) {
	snapshot := func() (map[string]bool, string) {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("requires Linux process metadata")
		}
		sockets := map[string]bool{}
		for _, fd := range fds {
			target, _ := os.Readlink("/proc/self/fd/" + fd.Name())
			if len(target) > 7 && target[:7] == "socket:" {
				sockets[target] = true
			}
		}
		tasks, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatal(err)
		}
		var children string
		for _, task := range tasks {
			b, _ := os.ReadFile("/proc/self/task/" + task.Name() + "/children")
			children += string(b)
		}
		return sockets, children
	}
	before, children := snapshot()
	server, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := StartClient(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	after, newChildren := snapshot()
	for socket := range after {
		if !before[socket] {
			t.Fatalf("native endpoint opened socket %s", socket)
		}
	}
	if newChildren != children {
		t.Fatal("native endpoint started a child process")
	}
}

func TestNativeServerSelectsOnlyDeviceSuiteWithoutIdentityHint(t *testing.T) {
	// Literal fixture follows the observed extension-free device ClientHello.
	hello := []byte{0x16, 3, 3, 0, 47, 1, 0, 0, 43, 3, 3}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0, 0, 4, 0, 0xae, 0, 0xff, 1, 0)
	server, err := Start(context.Background(), Config{PSK: ReferencePSK()})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// Feed one byte at a time, proving native BIO framing survives partial headers.
	for _, b := range hello {
		if _, err := server.Device().Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.Device().SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 1024)
	n, err := server.Device().Read(out)
	if err != nil {
		t.Fatal(err)
	}
	out = out[:n]
	var types []byte
	for len(out) > 0 {
		if len(out) < 9 {
			t.Fatalf("short generated handshake")
		}
		length := int(out[3])<<8 | int(out[4])
		if length+5 > len(out) {
			t.Fatalf("short generated record")
		}
		if out[0] != 22 {
			t.Fatalf("unexpected generated record type %d", out[0])
		}
		body := out[5 : 5+length]
		types = append(types, body[0])
		if body[0] == 2 {
			if len(body) < 42 || body[4] != 3 || body[5] != 3 {
				t.Fatal("server did not select TLS1.2")
			}
			suiteOffset := 39 + int(body[38])
			if body[suiteOffset] != 0 || body[suiteOffset+1] != 0xae {
				t.Fatal("server selected non-device suite")
			}
		}
		out = out[5+length:]
	}
	if !bytes.Equal(types, []byte{2, 14}) {
		t.Fatalf("server flight types %v; expected ServerHello, ServerHelloDone with no PSK identity hint", types)
	}
}

func TestOpenSSLSystemProtocolAndCipherRestrictions(t *testing.T) {
	if os.Getenv("GOODIX_RESTRICTED_POLICY_CHILD") == "1" {
		if err := Preflight(context.Background()); !errors.Is(err, ErrPolicy) {
			t.Fatalf("system policy restriction bypassed: %v", err)
		}
		if s, err := Start(context.Background(), Config{PSK: ReferencePSK()}); !errors.Is(err, ErrPolicy) {
			if s != nil {
				s.Close()
			}
			t.Fatalf("Start broadened system policy: %v", err)
		}
		return
	}
	for _, restriction := range []string{"MinProtocol = TLSv1.3", "MaxProtocol = TLSv1.1", "CipherString = AES128-SHA"} {
		t.Run(restriction, func(t *testing.T) {
			conf := filepath.Join(t.TempDir(), "openssl.cnf")
			content := "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = policy\n[policy]\n" + restriction + "\n"
			if err := os.WriteFile(conf, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOpenSSLSystemProtocolAndCipherRestrictions$", "-test.count=1")
			cmd.Env = append(os.Environ(), "OPENSSL_CONF="+conf, "GOODIX_RESTRICTED_POLICY_CHILD=1")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v\n%s", restriction, err, out)
			}
		})
	}
}

func TestNativeHandshakeClassifiesDifferentPSKs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	server, err := Start(ctx, Config{PSK: bytes.Repeat([]byte{0x11}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := StartClient(ctx, Config{PSK: bytes.Repeat([]byte{0x22}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result := make(chan error, 1)
	go func() { _, err := io.Copy(server.Device(), client.Device()); result <- err }()
	go func() { _, _ = io.Copy(client.Device(), server.Device()) }()
	select {
	case err := <-result:
		if !errors.Is(err, ErrPSKMismatch) {
			t.Fatalf("different keys not classified as likely PSK mismatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("different keys handshake hung")
	}
}
