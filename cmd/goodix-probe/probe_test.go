package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// replayCounters is the test-only view of the replay transport.
type replayCounters interface {
	Remaining() int
	Unread() int
}

// runReplay runs a bisect over script's commands, keyboard checks assumed, and
// returns its log.
func runReplay(t *testing.T, script []transport.Exchange) (string, replayCounters) {
	t.Helper()
	var buf bytes.Buffer
	tr := transport.NewReplay(script, transport.Options{Ceiling: proto.ClassSafe})
	t.Cleanup(func() { tr.Close() })

	var ops []proto.Opcode
	for _, ex := range script {
		ops = append(ops, ex.Cmd)
	}
	open := func() (transport.Transport, error) { return tr, nil }
	if err := runBisect(log.New(&buf, "", 0), assumeKeysHost{}, open, ops, 50*time.Millisecond, 0, healthOff, nil); err != nil {
		t.Fatalf("runBisect: %v\n%s", err, buf.String())
	}
	return buf.String(), tr.(replayCounters)
}

// section returns the log lines between the last header named name and the
// next section header.
func section(t *testing.T, out, name string) string {
	t.Helper()
	start := strings.LastIndex(out, "--- "+name+" ")
	if start < 0 {
		start = strings.LastIndex(out, "--- "+name+"\n")
	}
	if start < 0 {
		t.Fatalf("no section for %s in:\n%s", name, out)
	}
	rest := out[start+1:]
	if end := strings.Index(rest, "\n--- "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// Every transfer captured in Run 1 must decode, and each must be attributed to
// the right command now that the probe reads ACK and data separately.
func TestRun1CaptureDecodes(t *testing.T) {
	out, rt := runReplay(t, run1Script())

	for _, bad := range []string{"did not decode", "malformed ACK", "stray ACK"} {
		if strings.Contains(out, bad) {
			t.Errorf("log contains %q:\n%s", bad, out)
		}
	}

	// nop is no longer a step, so the unsolicited 0x32 that arrived on attach
	// leads the firmware_version section — the order it was seen on the wire.
	// It must still be reported as unsolicited and must not be mistaken for a
	// reply, which is the mistake Run 1's one-read-per-command loop made.
	fw := section(t, out, "step 1 firmware_version")
	for _, want := range []string{
		"unsolicited message cmd=0x32",
		"ACK for firmware_version (0xa8), status 0x01",
		"data for firmware_version",
		`"GF_ITE_EC_20063"`,
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("firmware_version section lacks %q:\n%s", want, fw)
		}
	}

	if n := rt.Remaining(); n != 0 {
		t.Errorf("%d scripted exchanges not sent", n)
	}
	if n := rt.Unread(); n != 0 {
		t.Errorf("%d transfers left unread in the device", n)
	}
}

// Transfers that arrive after a step has its data must be drained before the
// probe exits, not left queued in the EC.
func TestDrainEmptiesQueue(t *testing.T) {
	script := run1Script()
	extra := proto.Encode(0x32, []byte{0x01, 0x02})
	// The last step already gets its data, so extra arrives after it.
	last := &script[len(script)-1]
	last.Responses = append(last.Responses, extra)

	out, rt := runReplay(t, script)

	if n := rt.Unread(); n != 0 {
		t.Fatalf("%d transfers left unread:\n%s", n, out)
	}
	drain := section(t, out, "drain")
	if !strings.Contains(drain, "device quiet after 1 leftover transfer(s)") {
		t.Errorf("drain should have collected exactly one leftover:\n%s", drain)
	}
}

// A device that never stops sending must not hold the probe in a loop.
func TestReadsAreBounded(t *testing.T) {
	script := run1Script()
	noise := proto.Encode(0x32, nil)
	for range maxReadsPerStep + maxDrainReads + 5 {
		script[0].Responses = append(script[0].Responses, noise)
	}

	out, _ := runReplay(t, script)
	if !strings.Contains(out, "giving up") {
		t.Errorf("drain did not give up on an endless device:\n%s", out)
	}
}
