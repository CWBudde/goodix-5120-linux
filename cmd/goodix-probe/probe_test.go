package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// replayCounters is the test-only view of the replay transport.
type replayCounters interface {
	Remaining() int
	Unread() int
}

// runReplay runs the probe against script and returns its log.
func runReplay(t *testing.T, script []transport.Exchange) (string, replayCounters) {
	t.Helper()
	var buf bytes.Buffer
	tr := transport.NewReplay(script, transport.Options{Ceiling: proto.ClassSafe})
	t.Cleanup(func() { tr.Close() })

	if err := run(log.New(&buf, "", 0), tr, 0); err != nil {
		t.Fatalf("run: %v\n%s", err, buf.String())
	}
	return buf.String(), tr.(replayCounters)
}

// section returns the log lines between the header for opcode name and the
// next section header.
func section(t *testing.T, out, name string) string {
	t.Helper()
	start := strings.Index(out, "--- "+name+" ")
	if start < 0 {
		start = strings.Index(out, "--- "+name+"\n")
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

	nop := section(t, out, "nop")
	if !strings.Contains(nop, "unsolicited message cmd=0x32") || !strings.Contains(nop, "no ACK") {
		t.Errorf("nop section should show the unsolicited 0x32 and no ACK:\n%s", nop)
	}

	fw := section(t, out, "firmware_version")
	for _, want := range []string{"ACK for firmware_version (0xa8), status 0x01", "data for firmware_version", `"GF_ITE_EC_20063"`} {
		if !strings.Contains(fw, want) {
			t.Errorf("firmware_version section lacks %q:\n%s", want, fw)
		}
	}

	psk := section(t, out, "preset_psk_read")
	if !strings.Contains(psk, "ACK for preset_psk_read") || !strings.Contains(psk, "no data message") {
		t.Errorf("preset_psk_read section should show an ACK and no data:\n%s", psk)
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
	last := &script[len(script)-1]
	last.Responses = append(last.Responses, proto.Encode(last.Cmd, []byte{0x00}), extra)

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
