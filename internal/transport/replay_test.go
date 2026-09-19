package transport

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"goodix5120/internal/proto"
)

func TestReplayHappyPath(t *testing.T) {
	script := []Exchange{
		{Cmd: opFWVer, Payload: nil, Responses: [][]byte{{0xa0, 0x01, 0x02}}},
		{Cmd: opNOP, Payload: []byte{0x00, 0x00}, Responses: [][]byte{{0xb0}}},
	}
	tr := NewReplay(script, Options{})
	defer tr.Close()

	if err := tr.Send(opFWVer, nil); err != nil {
		t.Fatalf("Send(firmware_version): %v", err)
	}
	got, err := tr.Recv(0)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, script[0].Responses[0]) {
		t.Errorf("Recv = %x, want %x", got, script[0].Responses[0])
	}

	if err := tr.Send(opNOP, []byte{0x00, 0x00}); err != nil {
		t.Fatalf("Send(nop): %v", err)
	}
	if got, err = tr.Recv(0); err != nil || !bytes.Equal(got, script[1].Responses[0]) {
		t.Fatalf("Recv = %x, %v; want %x, nil", got, err, script[1].Responses[0])
	}

	if n := tr.(*replayTransport).Remaining(); n != 0 {
		t.Errorf("%d scripted exchanges left unconsumed", n)
	}
}

// The replay fake must apply the identical safety gate, since it shares
// checkOpcode with the USB path.
func TestReplayEnforcesSameCeiling(t *testing.T) {
	script := []Exchange{{Cmd: opReset, Responses: [][]byte{{0x01}}}}
	tr := NewReplay(script, Options{}) // default safe ceiling
	defer tr.Close()

	err := tr.Send(opReset, nil)
	if err == nil {
		t.Fatal("replay Send(reset) succeeded under the safe ceiling; it must be refused")
	}
	if !strings.Contains(err.Error(), "state-changing") {
		t.Errorf("error %q does not name the offending class", err)
	}
	if n := tr.(*replayTransport).Remaining(); n != 1 {
		t.Errorf("refused command consumed a scripted exchange (%d remaining, want 1)", n)
	}
	if _, err := tr.Recv(0); !errors.Is(err, ErrTimeout) {
		t.Errorf("Recv after a refused Send = %v, want ErrTimeout; no response should have been queued", err)
	}
}

func TestReplayRefusesUnregisteredOpcode(t *testing.T) {
	tr := NewReplay([]Exchange{{Cmd: opUnknwn}}, Options{Ceiling: proto.ClassDestructive})
	defer tr.Close()

	if err := tr.Send(opUnknwn, nil); err == nil || !strings.Contains(err.Error(), "unregistered") {
		t.Fatalf("Send of unregistered opcode = %v, want an 'unregistered' refusal", err)
	}
}

func TestReplayCommandMismatchNamesBoth(t *testing.T) {
	tr := NewReplay([]Exchange{{Cmd: opFWVer}}, Options{})
	defer tr.Close()

	err := tr.Send(opNOP, nil)
	if err == nil {
		t.Fatal("mismatched command was accepted")
	}
	for _, want := range []string{"firmware_version", "nop"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("mismatch error %q does not name %q", err, want)
		}
	}
}

func TestReplayPayloadMismatch(t *testing.T) {
	tr := NewReplay([]Exchange{{Cmd: opNOP, Payload: []byte{0x01}}}, Options{})
	defer tr.Close()

	if err := tr.Send(opNOP, []byte{0x02}); err == nil || !strings.Contains(err.Error(), "payload mismatch") {
		t.Fatalf("Send with wrong payload = %v, want a payload mismatch error", err)
	}
}

func TestReplayNilPayloadSkipsCheck(t *testing.T) {
	tr := NewReplay([]Exchange{{Cmd: opNOP, Payload: nil, Responses: [][]byte{{0x09}}}}, Options{})
	defer tr.Close()

	if err := tr.Send(opNOP, []byte{0xff, 0xee}); err != nil {
		t.Fatalf("nil scripted payload should accept any payload, got %v", err)
	}
}

func TestReplayScriptExhausted(t *testing.T) {
	tr := NewReplay(nil, Options{})
	defer tr.Close()

	if err := tr.Send(opNOP, nil); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("Send against an empty script = %v, want an 'exhausted' error", err)
	}
}

func TestReplayCloseIsIdempotentAndBlocks(t *testing.T) {
	tr := NewReplay([]Exchange{{Cmd: opNOP}}, Options{})
	if err := tr.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := tr.Send(opNOP, nil); err == nil {
		t.Error("Send succeeded after Close")
	}
	if _, err := tr.Recv(0); err == nil {
		t.Error("Recv succeeded after Close")
	}
}

// The device sends an ACK and a data message per command. A caller that reads
// once per command must fall one transfer behind, not lose the data: this is
// what happened in Run 1.
func TestReplayQueueOutlivesSend(t *testing.T) {
	ack, data, next := []byte{0x01}, []byte{0x02}, []byte{0x03}
	tr := NewReplay([]Exchange{
		{Cmd: opFWVer, Responses: [][]byte{ack, data}},
		{Cmd: opNOP, Responses: [][]byte{next}},
	}, Options{})
	defer tr.Close()
	rt := tr.(*replayTransport)

	if err := tr.Send(opFWVer, nil); err != nil {
		t.Fatalf("Send(firmware_version): %v", err)
	}
	if got, _ := tr.Recv(0); !bytes.Equal(got, ack) {
		t.Fatalf("first Recv = %x, want the ACK %x", got, ack)
	}
	if err := tr.Send(opNOP, nil); err != nil {
		t.Fatalf("Send(nop): %v", err)
	}
	for _, want := range [][]byte{data, next} {
		if got, err := tr.Recv(0); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Recv = %x, %v; want %x in FIFO order", got, err, want)
		}
	}
	if n := rt.Unread(); n != 0 {
		t.Errorf("%d transfers left unread", n)
	}
	if _, err := tr.Recv(0); !errors.Is(err, ErrTimeout) {
		t.Errorf("Recv on an empty queue = %v, want ErrTimeout", err)
	}
}

func TestReplaySilentExchangeTimesOut(t *testing.T) {
	tr := NewReplay([]Exchange{{Cmd: opNOP}}, Options{})
	defer tr.Close()

	if err := tr.Send(opNOP, nil); err != nil {
		t.Fatalf("Send(nop): %v", err)
	}
	if _, err := tr.Recv(0); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Recv after a silent exchange = %v, want ErrTimeout", err)
	}
}
