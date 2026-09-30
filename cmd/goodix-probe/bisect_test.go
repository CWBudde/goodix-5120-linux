package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"slices"
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
	ops, err := parseSteps(list)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	host := &fakeHost{presses: presses}
	tr := transport.NewReplay(scriptFor(ops), transport.Options{Ceiling: proto.ClassSafe})
	opened := false
	open := func() (transport.Transport, error) { opened = true; return tr, nil }

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second, healthOff, nil)
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
	got, err := parseSteps(" 0xA8, ae ,")
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
		if _, err := parseSteps(ok); err != nil {
			t.Errorf("parseSteps(%q) refused: %v", ok, err)
		}
	}

	// Refused with no allow set: the two above-ceiling frames (preset_psk_read
	// needs --allow-e4, reset needs --allow-a2), the destructive opcodes,
	// everything else above the safe ceiling, nop (the vendor never sends it, so
	// there is no payload to copy) and junk.
	for _, bad := range []string{"e4", "a2", "f0", "e0", "20", "90", "d0", "00", "zz", "100"} {
		if _, err := parseSteps(bad); err == nil {
			t.Errorf("parseSteps(%q) accepted", bad)
		}
	}

	// An allow entry admits exactly its opcode and nothing else that was refused
	// without it.
	if got, err := parseSteps("e4", opPSKRead); err != nil || len(got) != 1 || got[0] != opPSKRead {
		t.Errorf("parseSteps(e4, opPSKRead) = %v, %v", got, err)
	}
	if got, err := parseSteps("a2", opReset); err != nil || len(got) != 1 || got[0] != opReset {
		t.Errorf("parseSteps(a2, opReset) = %v, %v", got, err)
	}
	// One flag does not unlock the other's opcode.
	if _, err := parseSteps("a2", opPSKRead); err == nil {
		t.Error("parseSteps(a2, opPSKRead) accepted a2 under the e4 allow")
	}
	if _, err := parseSteps("e4", opReset); err == nil {
		t.Error("parseSteps(e4, opReset) accepted e4 under the a2 allow")
	}
	// Both together admit both, in order.
	if got, err := parseSteps("a2,e4", opReset, opPSKRead); err != nil || len(got) != 2 || got[0] != opReset || got[1] != opPSKRead {
		t.Errorf("parseSteps(a2,e4, opReset, opPSKRead) = %v, %v", got, err)
	}
	// The allow set never lowers the bar for the destructive or nonsense opcodes.
	for _, bad := range []string{"f0", "e0", "20", "90", "d0", "00"} {
		if _, err := parseSteps(bad, opPSKRead, opReset); err == nil {
			t.Errorf("parseSteps(%q, allow all) accepted", bad)
		}
	}
}

// With --allow-e4, preset_psk_read reaches the device through the transport's
// Allow exception while the ceiling stays safe; without it, the transport
// still refuses it. The replay answers with the ACK Runs 1 and 2 saw.
func TestBisectAllowE4(t *testing.T) {
	ops, err := parseSteps("e4", opPSKRead)
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

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second, healthOff, nil)
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

// With --allow-a2, reset reaches the device through the transport's Allow
// exception while the ceiling stays safe; without it, the transport refuses it.
// Unlike 0xe4 the reset does not wedge the EC, so the run completes with the
// keyboard alive after every step.
func TestBisectAllowA2(t *testing.T) {
	ops, err := parseSteps("a2", opReset)
	if err != nil {
		t.Fatal(err)
	}

	refusing := transport.NewReplay(scriptFor(ops), transport.Options{Ceiling: proto.ClassSafe})
	if err := refusing.Send(opReset, nil); !errors.Is(err, transport.ErrRefused) {
		t.Fatalf("0xa2 without Allow: err = %v, want ErrRefused", err)
	}

	var buf bytes.Buffer
	tr := transport.NewReplay(scriptFor(ops), transport.Options{
		Ceiling: proto.ClassSafe,
		Allow:   []proto.Opcode{opReset},
	})
	open := func() (transport.Transport, error) { return tr, nil }
	// baseline ok, attach ok, reset ok — the keyboard survives the reset.
	host := &fakeHost{presses: []bool{true, true, true}}

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second, healthOff, nil)
	if err != nil {
		t.Fatalf("runBisect with --allow-a2 = %v\n%s", err, buf.String())
	}
	if out := buf.String(); !strings.Contains(out, "keyboard alive after step 1 reset (0xa2)") {
		t.Errorf("reset step not run as expected:\n%s", out)
	}
}

// Everything bisect may send without --allow-e4 must be ClassSafe.
func TestBisectStepsAreSafe(t *testing.T) {
	ops, err := parseSteps(defaultBisectSteps())
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

// TestHealthCheckStopsBeforeTheFirstStep is Run 12's regression test. That run
// began with an EC that answered nothing, sent ten frames into it anyway, and
// lost the internal keyboard at step 8. The health check must stop such a run
// before the first step, and it must not be reported as a keyboard failure —
// the keyboard was fine, the EC was not.
func TestHealthCheckStopsBeforeTheFirstStep(t *testing.T) {
	ops, err := parseSteps("a8,ae")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	host := &fakeHost{}
	// An exchange that accepts the probe and answers nothing: exactly what Run 12
	// saw from a stuck EC, which took the frame and stayed silent.
	silent := []transport.Exchange{{Cmd: opFirmwareVer}}
	tr := transport.NewReplay(silent, transport.Options{Ceiling: proto.ClassSafe})
	open := func() (transport.Transport, error) { return tr, nil }

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second, healthCheck, nil)
	if !errors.Is(err, errECUnresponsive) {
		t.Fatalf("runBisect with an unresponsive EC = %v, want errECUnresponsive\nlog:\n%s", err, &buf)
	}
	if errors.Is(err, errKeyboardLost) {
		t.Error("an unresponsive EC was reported as a lost keyboard")
	}
	if got := buf.String(); !strings.Contains(got, "health check") {
		t.Errorf("the log does not mention the health check:\n%s", got)
	}
	// The steps must not have run. step 1 is the first thing after the check.
	if got := buf.String(); strings.Contains(got, "--- step 1") {
		t.Errorf("a step ran after the health check failed:\n%s", got)
	}
}

// TestHealthCheckPassesOnAnAnsweringEC is the other half: a healthy EC answers
// 0xa8 and the run proceeds normally.
func TestHealthCheckPassesOnAnAnsweringEC(t *testing.T) {
	ops, err := parseSteps("a8")
	if err != nil {
		t.Fatal(err)
	}
	// Two a8 exchanges: one for the health check, one for the step itself.
	script := append(scriptFor(ops), scriptFor(ops)...)
	var buf bytes.Buffer
	host := &fakeHost{}
	tr := transport.NewReplay(script, transport.Options{Ceiling: proto.ClassSafe})
	open := func() (transport.Transport, error) { return tr, nil }

	if err := runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second, healthCheck, nil); err != nil {
		t.Fatalf("runBisect with a healthy EC = %v\nlog:\n%s", err, &buf)
	}
	if got := buf.String(); !strings.Contains(got, "the run may proceed") {
		t.Errorf("the health check did not report success:\n%s", got)
	}
	// Run 16: the version string follows the ACK, and the health check must
	// read it rather than leave it for the drain to call unsolicited.
	if got := buf.String(); strings.Contains(got, "unsolicited message cmd=0xa8") {
		t.Errorf("the health check left its own reply for the drain:\n%s", got)
	}
	// Run 18: the health check read the ACK itself, then logged the version
	// string as "data arrived with no ACK".
	if got := buf.String(); strings.Contains(got, "no ACK") {
		t.Errorf("the health check forgot the ACK it read:\n%s", got)
	}
}

// run12State is the 0xae reply Run 12 received from the EC Run 11 left inside
// an unfinished handshake (goodix-bisect-20260920-161701.log): status 0x08,
// counter 0x14. Observed, not invented.
var run12State = []byte{
	0x02, 0x08, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x90, 0x63,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x14,
}

// runReadState runs a bisect with --read-state against an EC that ignores 0xa8
// and answers 0xae with state (nil: answers nothing).
func runReadState(t *testing.T, state []byte, presses ...bool) (string, *fakeHost, error) {
	t.Helper()
	ops, err := parseSteps("a8,ae")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := stepFor(opMCUState)
	ae := transport.Exchange{Cmd: opMCUState, Payload: st.payload}
	if state != nil {
		ae.Responses = [][]byte{dataFor(opMCUState, state)}
	}
	script := []transport.Exchange{{Cmd: opFirmwareVer}, ae}
	tr := transport.NewReplay(script, transport.Options{Ceiling: proto.ClassSafe})
	open := func() (transport.Transport, error) { return tr, nil }

	var buf bytes.Buffer
	host := &fakeHost{presses: presses}
	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, time.Second, healthReadState, nil)
	return buf.String(), host, err
}

// TestReadStateOnAStuckEC replays Run 12's EC under --read-state: 0xa8 goes
// unanswered, exactly one 0xae follows, the verdict names the stuck handshake,
// the keyboard is checked after it, and the run still stops before any step.
// The replay script holds only those two exchanges, so any further frame would
// fail the run with a script error instead of errECUnresponsive.
func TestReadStateOnAStuckEC(t *testing.T) {
	out, host, err := runReadState(t, run12State)
	if !errors.Is(err, errECUnresponsive) {
		t.Fatalf("err = %v, want errECUnresponsive\n%s", err, out)
	}
	for _, want := range []string{"--read-state", "status 0x08", "trailing counter 0x14", "still Run 12's state"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--- step 1") {
		t.Errorf("a step ran after the health check failed:\n%s", out)
	}
	// baseline, attach, read-state.
	if host.checks != 3 {
		t.Errorf("keyboard checks = %d, want 3 (baseline, attach, read-state)", host.checks)
	}
}

// TestReadStateKeyboardLost: if the keyboard dies after the 0xae, that is what
// the run reports — it is the more important of the two facts.
func TestReadStateKeyboardLost(t *testing.T) {
	out, _, err := runReadState(t, run12State, true, true, false)
	if !errors.Is(err, errKeyboardLost) || !strings.Contains(err.Error(), "read-state") {
		t.Fatalf("err = %v, want errKeyboardLost after read-state\n%s", err, out)
	}
}

// TestReadStateSilentEC: an EC that ignores 0xae as well gets the "worse than
// Run 12" verdict, and nothing else is sent to it.
func TestReadStateSilentEC(t *testing.T) {
	out, _, err := runReadState(t, nil)
	if !errors.Is(err, errECUnresponsive) {
		t.Fatalf("err = %v, want errECUnresponsive\n%s", err, out)
	}
	if !strings.Contains(out, "not even 0xae") {
		t.Errorf("log lacks the silent-EC verdict:\n%s", out)
	}
}

// TestStuckVerdict pins how a 0xae reply is read: Run 12's state, an EC whose
// counter went back down (it was reset), and a status never seen when stuck.
func TestStuckVerdict(t *testing.T) {
	withStatus := func(status, counter byte) *proto.MCUState {
		raw := slices.Clone(run12State)
		raw[1], raw[18], raw[19] = status, counter, counter
		s, err := proto.DecodeMCUState(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &s
	}
	for _, tc := range []struct {
		name  string
		state *proto.MCUState
		want  string
	}{
		{"silent", nil, "not even 0xae"},
		{"run 12", withStatus(0x08, 0x16), "still Run 12's state"},
		{"reset, cold init status", withStatus(0x11, 0x02), "the counter went DOWN"},
		{"tls up, counter higher", withStatus(0x02, 0x16), "a status not seen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(stuckVerdict(tc.state), "\n"); !strings.Contains(got, tc.want) {
				t.Errorf("verdict = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// TestHealthCheckIgnoresUnsolicitedEvents: a 0x32 finger-detect event is not
// an answer to 0xa8. An EC that sends one and then nothing is still stuck, and
// the run must stop.
func TestHealthCheckIgnoresUnsolicitedEvents(t *testing.T) {
	ops, err := parseSteps("a8")
	if err != nil {
		t.Fatal(err)
	}
	fdt := dataFor(0x32, []byte{0x02, 0x00, 0x2f, 0x00, 0x1e, 0x01, 0x38, 0x01, 0xff, 0x00, 0xf7, 0x00, 0x3f, 0x01, 0x34, 0x01})
	script := []transport.Exchange{{Cmd: opFirmwareVer, Responses: [][]byte{fdt}}}
	tr := transport.NewReplay(script, transport.Options{Ceiling: proto.ClassSafe})
	open := func() (transport.Transport, error) { return tr, nil }

	var buf bytes.Buffer
	err = runBisect(log.New(&buf, "", 0), &fakeHost{}, open, ops, 0, time.Second, healthCheck, nil)
	if !errors.Is(err, errECUnresponsive) {
		t.Fatalf("runBisect with only an unsolicited 0x32 = %v, want errECUnresponsive\nlog:\n%s", err, &buf)
	}
}
