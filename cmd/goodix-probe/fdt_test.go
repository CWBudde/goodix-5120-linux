package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// fifo is a Transport that hands out queued transfers and times out when empty.
// It sends nothing anywhere; Send records the frame.
type fifo struct {
	in   [][]byte
	sent []proto.Opcode
}

func (f *fifo) Send(cmd proto.Opcode, _ []byte) error { f.sent = append(f.sent, cmd); return nil }
func (f *fifo) SendTLS([]byte) error                  { return errors.New("fifo: no TLS") }
func (f *fifo) Close() error                          { return nil }
func (f *fifo) Recv(time.Duration) ([]byte, error) {
	if len(f.in) == 0 {
		return nil, transport.ErrTimeout
	}
	out := f.in[0]
	f.in = f.in[1:]
	return out, nil
}

// waitFDTEvent must read past the arm's ACK, and past anything unexpected, to
// the event — the vendor's arms are acknowledged before the finger arrives.
func TestWaitFDTEventReadsPastTheACK(t *testing.T) {
	var buf bytes.Buffer
	tr := &fifo{in: [][]byte{
		proto.Encode(proto.AckCmd, []byte{byte(opFDTDown), 0x01}),
		{},
		proto.Encode(0xae, make([]byte, 20)),
		proto.Encode(opFDTDown, rehearsalDown),
	}}
	ev, err := waitFDTEvent(context.Background(), log.New(&buf, "", 0), tr, opFDTDown, time.Second)
	if err != nil {
		t.Fatalf("waitFDTEvent: %v\n%s", err, buf.String())
	}
	if ev.Kind != proto.FDTEventDown || ev.Flags != 0x2f {
		t.Errorf("event = %s, want finger down with flags 0x2f", ev)
	}
	for _, want := range []string{"ACK for 0x32", "unexpected 0xae"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log does not mention %q:\n%s", want, buf.String())
		}
	}
}

func TestWaitFDTEventTimesOut(t *testing.T) {
	tr := &fifo{in: [][]byte{proto.Encode(proto.AckCmd, []byte{byte(opFDTUp), 0x01})}}
	_, err := waitFDTEvent(context.Background(), log.New(&bytes.Buffer{}, "", 0), tr, opFDTUp, 50*time.Millisecond)
	if !errors.Is(err, errNoFinger) {
		t.Fatalf("err = %v, want errNoFinger", err)
	}
}

// The catalogued arms must decode, since --wait-finger starts from the down
// arm's thresholds, and the rehearsal's events must be the kinds it claims.
func TestFDTCatalogueAndRehearsalEvents(t *testing.T) {
	for _, op := range []proto.Opcode{opFDTDown, opFDTUp} {
		st, ok := stepFor(op)
		if !ok {
			t.Fatalf("no catalogue entry for 0x%02x", byte(op))
		}
		if _, err := proto.DecodeFDTArm(op, st.payload); err != nil {
			t.Errorf("catalogued 0x%02x arm: %v", byte(op), err)
		}
	}
	for _, c := range []struct {
		op   proto.Opcode
		raw  []byte
		want proto.FDTEventKind
	}{
		{opFDTDown, rehearsalBaseInvalid, proto.FDTEventBaseInvalid},
		{opFDTDown, rehearsalDown, proto.FDTEventDown},
		{opFDTUp, rehearsalUp, proto.FDTEventUp},
	} {
		ev, err := proto.DecodeFDTEvent(c.op, c.raw)
		if err != nil || ev.Kind != c.want {
			t.Errorf("rehearsal event %x = %v, %v; want %v", c.raw, ev.Kind, err, c.want)
		}
	}
}

func TestWaitFingerOpcodes(t *testing.T) {
	cfg := tlsConfig{enabled: true, getImage: true, waitFinger: true, armDown: true, armUp: true}
	got := opList(cfg.opcodes())
	if got != "d0,20,32,34" {
		t.Errorf("--wait-finger run sends %s, want d0,20,32,34", got)
	}
	cfg.waitFinger = false
	if got := opList(cfg.opcodes()); got != "d0,20" {
		t.Errorf("without --wait-finger the flags admit %s, want d0,20", got)
	}
}

func TestTouchPath(t *testing.T) {
	for _, c := range []struct {
		path     string
		n, total int
		want     string
	}{
		{"captures/frame.pgm", 1, 1, "captures/frame.pgm"},
		{"captures/frame.pgm", 1, 3, "captures/frame-1.pgm"},
		{"captures/frame.pgm", 3, 3, "captures/frame-3.pgm"},
		{"frame", 2, 2, "frame-2"},
	} {
		if got := touchPath(c.path, c.n, c.total); got != c.want {
			t.Errorf("touchPath(%q, %d, %d) = %q, want %q", c.path, c.n, c.total, got, c.want)
		}
	}
}

// TestSeveralTouchesInOneSession rehearses --touches end to end: one
// handshake, then three rounds of arm down, 0x20, arm up, each frame decrypted
// and written. The stand-in answers only the run's first arm with base
// invalid, and each later down arm must be derived from the previous lift.
func TestSeveralTouchesInOneSession(t *testing.T) {
	dir := t.TempDir()
	// Rehearsal must succeed even when an optional device-key path is missing.
	psk := filepath.Join(dir, "missing-device-key.bin")
	allowed := map[proto.Opcode]bool{opRequestTLS: true, opTLSEstablished: true, opGetImage: true, opFDTDown: true, opFDTUp: true}
	var allow []proto.Opcode
	for op := range allowed {
		allow = append(allow, op)
	}
	cfg := tlsConfig{
		enabled: true, pskPath: psk, capture: filepath.Join(dir, "frame.pgm"),
		sendD4: true, getImage: true,
		waitFinger: true, touches: 3, fingerTimeout: 5 * time.Second, armDown: true, armUp: true,
	}
	logPath := filepath.Join(dir, "run.log")

	// mainBisect also writes to stdout; the log file is what is checked.
	stdout := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = devnull
	code := mainBisect(true, false, false, allow, allowed, cfg, "a8", logPath, time.Second)
	os.Stdout = stdout
	_ = devnull.Close()

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if code != 0 {
		t.Fatalf("mainBisect = %d, want 0\n%s", code, out)
	}
	for n := 1; n <= 3; n++ {
		if _, err := os.Stat(touchPath(cfg.capture, n, 3)); err != nil {
			t.Errorf("frame %d not written: %v", n, err)
		}
	}
	if got := strings.Count(out, "handshake complete"); got != 1 {
		t.Errorf("%d handshakes, want exactly 1 for all three touches", got)
	}
	if got := strings.Count(out, "re-arming with"); got != 1 {
		t.Errorf("%d base-invalid re-arms, want 1 (only the run's first arm)", got)
	}
	if got := strings.Count(out, "the next down arm uses"); got != 2 {
		t.Errorf("%d down arms derived from a lift, want 2", got)
	}
	if !strings.Contains(out, "3 frames in one TLS session") {
		t.Errorf("the log does not report three frames in one session:\n%s", out)
	}
}
