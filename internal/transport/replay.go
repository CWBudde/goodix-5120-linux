package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"goodix5120/internal/proto"
)

// Exchange is one scripted request/response pair for the replay transport.
type Exchange struct {
	// Cmd is the opcode the caller is expected to send at this step.
	Cmd proto.Opcode
	// Payload is the expected outbound payload. Nil means "do not check".
	Payload []byte
	// Response is the raw byte slice the matching Recv will return.
	Response []byte
}

// replayTransport plays a fixed script, letting the probe run with no hardware
// attached. It enforces exactly the same safety rules as the USB transport,
// because both funnel Send through the shared sender/checkOpcode pair.
type replayTransport struct {
	sender

	script  []Exchange
	next    int    // index of the next expected exchange
	pending []byte // response queued by the last Send, awaiting Recv
	armed   bool   // whether pending holds a response
	closed  bool
}

// NewReplay returns a Transport that replays script.
func NewReplay(script []Exchange, opts Options) Transport {
	t := &replayTransport{script: script}
	t.sender = sender{opts: opts.withDefaults(), write: t.record}
	return t
}

// record is the frameWriter half of the replay: it checks the outbound command
// against the script and queues the scripted response for the next Recv.
func (t *replayTransport) record(_ context.Context, cmd proto.Opcode, payload, _ []byte) error {
	if t.closed {
		return errors.New("replay transport is closed")
	}
	if t.next >= len(t.script) {
		return fmt.Errorf("replay script exhausted after %d exchanges: unexpected send of %s (0x%02x)",
			len(t.script), cmd.Name(), byte(cmd))
	}

	want := t.script[t.next]
	if cmd != want.Cmd {
		return fmt.Errorf("replay mismatch at exchange %d: script expects %s (0x%02x) but %s (0x%02x) was sent",
			t.next, want.Cmd.Name(), byte(want.Cmd), cmd.Name(), byte(cmd))
	}
	if want.Payload != nil && !bytes.Equal(want.Payload, payload) {
		return fmt.Errorf("replay payload mismatch at exchange %d for %s (0x%02x): script expects %s but %s was sent",
			t.next, want.Cmd.Name(), byte(want.Cmd), hex.EncodeToString(want.Payload), hex.EncodeToString(payload))
	}

	t.next++
	t.pending, t.armed = want.Response, true
	return nil
}

// Recv returns the response scripted for the most recent Send. The timeout is
// accepted for interface compatibility and ignored: nothing here can block.
func (t *replayTransport) Recv(time.Duration) ([]byte, error) {
	if t.closed {
		return nil, errors.New("replay transport is closed")
	}
	if !t.armed {
		return nil, fmt.Errorf("replay has no queued response at exchange %d: Recv was called without a preceding successful Send", t.next)
	}

	out := t.pending
	t.pending, t.armed = nil, false
	t.opts.logf("transport: RX (replay) %d bytes: %s", len(out), hex.EncodeToString(out))
	return out, nil
}

// Close marks the transport unusable. It is safe to call more than once.
func (t *replayTransport) Close() error {
	t.closed = true
	t.pending, t.armed = nil, false
	return nil
}

// Remaining reports how many scripted exchanges have not been consumed. Tests
// use it to assert a script ran to completion.
func (t *replayTransport) Remaining() int {
	return len(t.script) - t.next
}
