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

// Exchange is one scripted command and the transfers the device sends back.
type Exchange struct {
	// Cmd is the opcode the caller is expected to send at this step. It is
	// ignored when TLS is set.
	Cmd proto.Opcode
	// Payload is the expected outbound payload — the TLS records themselves
	// when TLS is set. Nil means "do not check".
	Payload []byte
	// TLS marks an exchange the caller is expected to reach with SendTLS rather
	// than Send. A script that expects a command where the caller sends TLS
	// data, or the reverse, fails rather than quietly passing.
	TLS bool
	// Responses are the raw transfers the device sends after Cmd, in order.
	// Each one satisfies one Recv. Empty means the device stays silent.
	Responses [][]byte
}

// replayTransport plays a fixed script, letting the probe run with no hardware
// attached. It enforces exactly the same safety rules as the USB transport,
// because both funnel Send through the shared sender/checkOpcode pair.
//
// Responses go into a FIFO that outlives the Send that queued them, as on the
// real device: a caller that reads too little falls behind instead of losing
// data, and a Recv on an empty queue times out.
type replayTransport struct {
	sender

	script []Exchange
	next   int      // index of the next expected exchange
	queue  [][]byte // transfers sent by the device and not yet read
	closed bool
}

// NewReplay returns a Transport that replays script.
func NewReplay(script []Exchange, opts Options) Transport {
	t := &replayTransport{script: script}
	t.sender = sender{opts: opts.withDefaults(), write: t.record}
	return t
}

// record is the frameWriter half of the replay: it checks the outbound command
// against the script and queues the scripted responses.
func (t *replayTransport) record(_ context.Context, o outbound) error {
	if t.closed {
		return errors.New("replay transport is closed")
	}
	if t.next >= len(t.script) {
		return fmt.Errorf("replay script exhausted after %d exchanges: unexpected send of %s",
			len(t.script), describeOutbound(o))
	}

	want := t.script[t.next]
	switch {
	case want.TLS != o.tls:
		return fmt.Errorf("replay mismatch at exchange %d: script expects %s but %s was sent",
			t.next, describeExchange(want), describeOutbound(o))
	case !o.tls && o.cmd != want.Cmd:
		return fmt.Errorf("replay mismatch at exchange %d: script expects %s (0x%02x) but %s (0x%02x) was sent",
			t.next, want.Cmd.Name(), byte(want.Cmd), o.cmd.Name(), byte(o.cmd))
	}
	if want.Payload != nil && !bytes.Equal(want.Payload, o.payload) {
		// A TLS payload is ciphertext, and the plaintext under it is a
		// fingerprint image, so the mismatch reports lengths rather than bytes.
		if o.tls {
			return fmt.Errorf("replay TLS mismatch at exchange %d: script expects %d record byte(s) but %d were sent",
				t.next, len(want.Payload), len(o.payload))
		}
		return fmt.Errorf("replay payload mismatch at exchange %d for %s (0x%02x): script expects %s but %s was sent",
			t.next, want.Cmd.Name(), byte(want.Cmd), hex.EncodeToString(want.Payload), hex.EncodeToString(o.payload))
	}

	t.next++
	t.queue = append(t.queue, want.Responses...)
	return nil
}

// describeOutbound names what was sent, for a mismatch message.
func describeOutbound(o outbound) string {
	if o.tls {
		return fmt.Sprintf("TLS data (%d byte(s))", len(o.payload))
	}
	return fmt.Sprintf("%s (0x%02x)", o.cmd.Name(), byte(o.cmd))
}

// describeExchange names what the script expected, for a mismatch message.
func describeExchange(e Exchange) string {
	if e.TLS {
		return "TLS data"
	}
	return fmt.Sprintf("%s (0x%02x)", e.Cmd.Name(), byte(e.Cmd))
}

// Recv returns the oldest unread transfer, or ErrTimeout if none is queued.
// The timeout itself is ignored: nothing here can block.
func (t *replayTransport) Recv(time.Duration) ([]byte, error) {
	if t.closed {
		return nil, errors.New("replay transport is closed")
	}
	if len(t.queue) == 0 {
		return nil, fmt.Errorf("replay has nothing queued after exchange %d: %w", t.next, ErrTimeout)
	}

	out := t.queue[0]
	t.queue = t.queue[1:]
	t.opts.logf("transport: RX (replay) %d bytes: %s", len(out), dump(out))
	return out, nil
}

// Close marks the transport unusable. It is safe to call more than once.
func (t *replayTransport) Close() error {
	t.closed = true
	t.queue = nil
	return nil
}

// Remaining reports how many scripted exchanges have not been consumed. Tests
// use it to assert a script ran to completion.
func (t *replayTransport) Remaining() int {
	return len(t.script) - t.next
}

// Unread reports how many transfers are queued but not yet read. Tests use it
// to assert a caller drained the device.
func (t *replayTransport) Unread() int {
	return len(t.queue)
}
