package main

import (
	"bytes"
	"errors"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// fakeHost records how often the host was logged and what was marked.
type fakeHost struct {
	snapshots int
	marks     []string
}

func (h *fakeHost) SensorPresent() bool { return true }
func (h *fakeHost) Snapshot() string    { h.snapshots++; return "fake" }
func (h *fakeHost) Mark(msg string)     { h.marks = append(h.marks, msg) }

// bisectReplay runs bisect over the Run 1 capture, using the default step list.
func bisectReplay(t *testing.T) (string, *fakeHost, replayCounters, bool, error) {
	t.Helper()
	return bisectReplaySteps(t, defaultBisectSteps())
}

// bisectReplaySteps is bisectReplay with an explicit --steps string, for tests
// that need more steps than the default list has. Repeats are legal, which is
// how a two-step run is built now that the probe sends exactly one command.
func bisectReplaySteps(t *testing.T, list string) (string, *fakeHost, replayCounters, bool, error) {
	t.Helper()
	ops, err := parseSteps(list)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	host := &fakeHost{}
	tr := transport.NewReplay(scriptFor(ops), transport.Options{Ceiling: proto.ClassSafe})
	opened := false
	open := func() (transport.Transport, error) { opened = true; return tr, nil }

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, healthOff, nil)
	return buf.String(), host, tr.(replayCounters), opened, err
}

func TestBisectAllStepsLogged(t *testing.T) {
	out, host, rt, _, err := bisectReplay(t)
	if err != nil {
		t.Fatalf("runBisect: %v\n%s", err, out)
	}
	if rt.Remaining() != 0 || rt.Unread() != 0 {
		t.Errorf("remaining=%d unread=%d, want 0/0", rt.Remaining(), rt.Unread())
	}
	// baseline + attach + one per step
	if want := 2 + len(steps); host.snapshots != want {
		t.Errorf("%d host log lines, want %d", host.snapshots, want)
	}
	if !strings.Contains(out, `as text "GF_ITE_EC_20063"`) {
		t.Errorf("version string not decoded:\n%s", out)
	}
	if !strings.Contains(out, "RESULT: every step completed") {
		t.Errorf("no final result:\n%s", out)
	}
	// The run asks nothing of the user.
	if strings.Contains(out, "press") || strings.Contains(out, ">>>") {
		t.Errorf("the run still prompts for input:\n%s", out)
	}
}

// A failed diagnostic transport must stop immediately and preserve its cause.
type stateFailureTransport struct {
	transport.Transport
	failure    error
	failSend   bool
	stateSent  bool
	stateReads int
}

func (tr *stateFailureTransport) Send(op proto.Opcode, payload []byte) error {
	if op == opMCUState {
		tr.stateSent = true
		if tr.failSend {
			return tr.failure
		}
		return nil
	}
	return tr.Transport.Send(op, payload)
}

func (tr *stateFailureTransport) Recv(timeout time.Duration) ([]byte, error) {
	if tr.stateSent {
		tr.stateReads++
		return nil, tr.failure
	}
	return tr.Transport.Recv(timeout)
}

func TestReadStatePreservesTransportError(t *testing.T) {
	for _, failSend := range []bool{true, false} {
		name := "receive"
		if failSend {
			name = "send"
		}
		t.Run(name, func(t *testing.T) {
			failure := errors.New("synthetic diagnostic I/O failure")
			tr := &stateFailureTransport{
				Transport: transport.NewReplay([]transport.Exchange{{Cmd: opFirmwareVer}}, transport.Options{Ceiling: proto.ClassSafe}),
				failure:   failure, failSend: failSend,
			}
			var out bytes.Buffer
			err := runBisect(log.New(&out, "", 0), &fakeHost{}, func() (transport.Transport, error) { return tr, nil },
				[]proto.Opcode{opFirmwareVer}, 0, healthReadState, nil)
			if !errors.Is(err, failure) {
				t.Fatalf("got %v, want diagnostic cause", err)
			}
			wantReads := 1
			if failSend {
				wantReads = 0
			}
			if tr.stateReads != wantReads {
				t.Fatalf("%d diagnostic reads, want %d; no drain after failure", tr.stateReads, wantReads)
			}
			if strings.Contains(out.String(), "--- step 1") {
				t.Fatal("step sent after failed diagnostic")
			}
		})
	}
}

func TestBisectFailedTailLogsHostAndPreservesError(t *testing.T) {
	tr := transport.NewReplay(scriptFor([]proto.Opcode{opFirmwareVer}), transport.Options{Ceiling: proto.ClassSafe})
	host := &fakeHost{}
	var out bytes.Buffer
	failure := errors.New("synthetic TLS tail failure")
	err := runBisect(log.New(&out, "", 0), host, func() (transport.Transport, error) { return tr, nil },
		[]proto.Opcode{opFirmwareVer}, 0, healthOff, func(transport.Transport) error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("got %v, want tail cause", err)
	}
	if host.snapshots != 4 || !strings.Contains(out.String(), "host after the after-steps hook") {
		t.Fatalf("missing passive host observation after failed tail:\n%s", out.String())
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
	err = runBisect(log.New(&buf, "", 0), &fakeHost{}, open, ops, 0, healthOff, nil)
	out := buf.String()
	if err != nil {
		t.Fatalf("runBisect with --allow-e4 = %v\n%s", err, out)
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
// The run completes.
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
	err = runBisect(log.New(&buf, "", 0), &fakeHost{}, open, ops, 0, healthOff, nil)
	if err != nil {
		t.Fatalf("runBisect with --allow-a2 = %v\n%s", err, buf.String())
	}
	if out := buf.String(); !strings.Contains(out, "host after step 1 reset (0xa2)") {
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

// TestHealthCheckStopsBeforeTheFirstStep is Run 12's regression test. That run
// began with an EC that answered nothing, sent ten frames into it anyway, and
// lost the internal keyboard at step 8. The health check must stop such a run
// before the first step.
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

	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, healthCheck, nil)
	if !errors.Is(err, errECUnresponsive) {
		t.Fatalf("runBisect with an unresponsive EC = %v, want errECUnresponsive\nlog:\n%s", err, &buf)
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

	if err := runBisect(log.New(&buf, "", 0), host, open, ops, 0, healthCheck, nil); err != nil {
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
func runReadState(t *testing.T, state []byte) (string, *fakeHost, error) {
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
	host := &fakeHost{}
	err = runBisect(log.New(&buf, "", 0), host, open, ops, 0, healthReadState, nil)
	return buf.String(), host, err
}

// TestReadStateOnAStuckEC replays Run 12's EC under --read-state: 0xa8 goes
// unanswered, exactly one 0xae follows, the verdict names the stuck handshake,
// the host is logged after it, and the run still stops before any step.
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
	if host.snapshots != 3 {
		t.Errorf("host log lines = %d, want 3 (baseline, attach, read-state)", host.snapshots)
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
	err = runBisect(log.New(&buf, "", 0), &fakeHost{}, open, ops, 0, healthCheck, nil)
	if !errors.Is(err, errECUnresponsive) {
		t.Fatalf("runBisect with only an unsolicited 0x32 = %v, want errECUnresponsive\nlog:\n%s", err, &buf)
	}
}
