package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// fakeHost answers keyboard checks from a script: presses[i] is the answer to
// the i-th check (baseline first). Checks past the end of the script pass.
type fakeHost struct {
	presses []bool
	checks  int
	marks   []string
}

func (h *fakeHost) WaitKey(time.Duration) (bool, error) {
	i := h.checks
	h.checks++
	if i < len(h.presses) {
		return h.presses[i], nil
	}
	return true, nil
}
func (h *fakeHost) SensorPresent() bool { return true }
func (h *fakeHost) Snapshot() string    { return "fake" }
func (h *fakeHost) Mark(msg string)     { h.marks = append(h.marks, msg) }

// bisectReplay runs bisect over the Run 1 capture with the given key presses,
// using the default step list.
func bisectReplay(t *testing.T, presses ...bool) (string, *fakeHost, replayCounters, bool, error) {
	t.Helper()
	return bisectReplaySteps(t, defaultBisectSteps(), presses...)
}

// bisectReplaySteps is bisectReplay with an explicit --steps string, for tests
// that need more steps than the default list has. Repeats are legal, which is
// how a two-step run is built now that the probe sends exactly one command.
func bisectReplaySteps(t *testing.T, list string, presses ...bool) (string, *fakeHost, replayCounters, bool, error) {
	t.Helper()
	ops, err := parseSteps(list, false)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	host := &fakeHost{presses: presses}
	tr := transport.NewReplay(scriptFor(ops), transport.Options{Ceiling: proto.ClassSafe})
	opened := false
	open := func() (transport.Transport, error) { opened = true; return tr, nil }

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second)
	return buf.String(), host, tr.(replayCounters), opened, err
}

func TestBisectAllStepsAlive(t *testing.T) {
	out, host, rt, _, err := bisectReplay(t)
	if err != nil {
		t.Fatalf("runBisect: %v\n%s", err, out)
	}
	if rt.Remaining() != 0 || rt.Unread() != 0 {
		t.Errorf("remaining=%d unread=%d, want 0/0", rt.Remaining(), rt.Unread())
	}
	// baseline + attach + one per step
	if want := 2 + len(steps); host.checks != want {
		t.Errorf("%d keyboard checks, want %d", host.checks, want)
	}
	if !strings.Contains(out, `as text "GF_ITE_EC_20063"`) {
		t.Errorf("version string not decoded:\n%s", out)
	}
	if !strings.Contains(out, "RESULT: internal keyboard alive after every step") {
		t.Errorf("no final result:\n%s", out)
	}
}

// A dead keyboard after a step must stop the run there: nothing further may be
// sent to the EC.
func TestBisectStopsAtFirstDeadCheck(t *testing.T) {
	// Two steps, so there is a second one left to not send. The probe's default
	// list is a single command now, and a repeat is the cheapest way to get a
	// second step without naming an opcode the probe would not otherwise send.
	//
	// baseline ok, attach ok, step 1 dead.
	out, host, rt, _, err := bisectReplaySteps(t, "a8,a8", true, true, false)
	if !errors.Is(err, errKeyboardLost) {
		t.Fatalf("err = %v, want errKeyboardLost\n%s", err, out)
	}
	if !strings.Contains(err.Error(), "firmware_version") {
		t.Errorf("error does not name the step: %v", err)
	}
	if rt.Remaining() != 1 {
		t.Errorf("remaining=%d, want 1: step 2 must not be sent after the keyboard died", rt.Remaining())
	}
	if strings.Contains(out, "step 2 ") {
		t.Errorf("step 2 was attempted:\n%s", out)
	}
	if last := host.marks[len(host.marks)-1]; !strings.HasPrefix(last, "NO KEY after step 1") {
		t.Errorf("last kernel marker = %q", last)
	}
}

// A keyboard that is dead before anything happens must stop the run before the
// device is even opened.
func TestBisectBaselineFailureOpensNothing(t *testing.T) {
	out, _, rt, opened, err := bisectReplay(t, false)
	if !errors.Is(err, errBaseline) {
		t.Fatalf("err = %v, want errBaseline\n%s", err, out)
	}
	if opened {
		t.Error("device was opened although the baseline check failed")
	}
	if rt.Remaining() != len(steps) {
		t.Errorf("remaining=%d, want %d", rt.Remaining(), len(steps))
	}
}

// Attach alone killing the keyboard must be reported as step 0, before any
// command is sent.
func TestBisectAttachFailure(t *testing.T) {
	_, _, rt, _, err := bisectReplay(t, true, false)
	if !errors.Is(err, errKeyboardLost) || !strings.Contains(err.Error(), "step 0 attach") {
		t.Fatalf("err = %v, want errKeyboardLost after step 0 attach", err)
	}
	if rt.Remaining() != len(steps) {
		t.Errorf("remaining=%d: a command was sent after attach failed", rt.Remaining())
	}
}

func TestParseSteps(t *testing.T) {
	got, err := parseSteps(" 0xA8, ae ,", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 0xa8 || got[1] != 0xae {
		t.Errorf("got %v", got)
	}

	// Every ClassSafe opcode whose vendor payload is on record is bisectable,
	// which is what lets PLAN.md Phase 4 add one command per live run without
	// widening the probe's own step list.
	for _, ok := range []string{"a8", "ae", "82", "a6"} {
		if _, err := parseSteps(ok, false); err != nil {
			t.Errorf("parseSteps(%q) refused: %v", ok, err)
		}
	}

	// Refused: preset_psk_read (needs --allow-e4), everything above the safe
	// ceiling, the destructive opcodes, nop (the vendor never sends it, so
	// there is no payload to copy) and junk.
	for _, bad := range []string{"e4", "f0", "e0", "a2", "20", "90", "d0", "00", "zz", "100"} {
		if _, err := parseSteps(bad, false); err == nil {
			t.Errorf("parseSteps(%q) accepted", bad)
		}
	}

	// --allow-e4 admits preset_psk_read, and admits nothing else that was
	// refused without it.
	if got, err := parseSteps("e4", true); err != nil || len(got) != 1 || got[0] != opPSKRead {
		t.Errorf("parseSteps(e4, allowE4) = %v, %v", got, err)
	}
	for _, bad := range []string{"f0", "e0", "a2", "20", "90", "d0", "00"} {
		if _, err := parseSteps(bad, true); err == nil {
			t.Errorf("parseSteps(%q, allowE4) accepted", bad)
		}
	}
}

// With --allow-e4, preset_psk_read reaches the device through the transport's
// Allow exception while the ceiling stays safe; without it, the transport
// still refuses it. The replay answers with the ACK Runs 1 and 2 saw.
func TestBisectAllowE4(t *testing.T) {
	ops, err := parseSteps("e4", true)
	if err != nil {
		t.Fatal(err)
	}

	refusing := transport.NewReplay(scriptFor(ops), transport.Options{Ceiling: proto.ClassSafe})
	if err := refusing.Send(opPSKRead, nil); !errors.Is(err, transport.ErrRefused) {
		t.Fatalf("0xe4 without Allow: err = %v, want ErrRefused", err)
	}

	var buf bytes.Buffer
	tr := transport.NewReplay(scriptFor(ops), transport.Options{
		Ceiling: proto.ClassSafe,
		Allow:   []proto.Opcode{opPSKRead},
	})
	open := func() (transport.Transport, error) { return tr, nil }
	// baseline ok, attach ok, 0xe4 dead — what Run 2 saw.
	host := &fakeHost{presses: []bool{true, true, false}}

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second)
	out := buf.String()
	if !errors.Is(err, errKeyboardLost) || !strings.Contains(err.Error(), "preset_psk_read") {
		t.Fatalf("err = %v, want errKeyboardLost after preset_psk_read\n%s", err, out)
	}
	if !strings.Contains(out, "ACK for preset_psk_read (0xe4), status 0x01") {
		t.Errorf("ACK not decoded:\n%s", out)
	}
	if rt := tr.(replayCounters); rt.Remaining() != 0 {
		t.Errorf("remaining=%d, want 0", rt.Remaining())
	}
}

// Everything bisect may send without --allow-e4 must be ClassSafe.
func TestBisectStepsAreSafe(t *testing.T) {
	ops, err := parseSteps(defaultBisectSteps(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if c, ok := op.Class(); !ok || c != proto.ClassSafe {
			t.Errorf("bisect step 0x%02x has class %v (registered %t)", byte(op), c, ok)
		}
	}
}

// inputEvent encodes a struct input_event as the kernel would.
func inputEvent(typ, code uint16, value int32) []byte {
	b := make([]byte, inputEventSize)
	tv := inputEventSize - 8
	binary.NativeEndian.PutUint16(b[tv:], typ)
	binary.NativeEndian.PutUint16(b[tv+2:], code)
	binary.NativeEndian.PutUint32(b[tv+4:], uint32(value))
	return b
}

// The evdev reader must count key-down events only, and presses made before
// WaitKey is called (such as the Enter that started the program) must not
// count as proof the keyboard is alive.
func TestLinuxHostKeyEvents(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	h := &linuxHost{keys: make(chan struct{}, 64), done: make(chan error, 1)}
	go h.read(r)

	const keyLeftShift = 42
	// An earlier press, before the prompt.
	w.Write(inputEvent(1, 28, 1))
	w.Write(inputEvent(0, 0, 0))
	time.Sleep(20 * time.Millisecond)

	// Release, autorepeat and sync alone are not a press.
	go func() {
		time.Sleep(20 * time.Millisecond)
		w.Write(inputEvent(1, 28, 0))
		w.Write(inputEvent(1, keyLeftShift, 2))
		w.Write(inputEvent(0, 0, 0))
	}()
	if ok, err := h.WaitKey(150 * time.Millisecond); ok || err != nil {
		t.Fatalf("WaitKey = %t, %v; want no press (stale press, release, repeat, sync only)", ok, err)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		w.Write(inputEvent(1, keyLeftShift, 1))
	}()
	if ok, err := h.WaitKey(time.Second); !ok || err != nil {
		t.Fatalf("WaitKey = %t, %v; want a press", ok, err)
	}
}
