package transport

import (
	"context"
	"errors"
	"time"
)

// Peer is an external stand-in for the sensor: something that accepts fully
// encoded packs and produces raw transfers, but is not the device.
//
// It exists for one reason. A rehearsal richer than the scripted replay — a
// stand-in that really completes a TLS handshake, say — cannot be expressed as a
// fixed list of Exchanges, but it must not therefore get a private write path:
// the whole safety model rests on every outbound byte passing through sender's
// gate (CLAUDE.md, "internal/transport is the single chokepoint"). NewPeer wraps
// a Peer in exactly that gate, so a rehearsal refuses the same frames the live
// USB path refuses, and an offline run proves something about the live one.
//
// A Peer must never be real hardware. The USB path is usbTransport, and it is
// the only thing in this repository that opens a device.
type Peer interface {
	// WritePack receives one fully encoded pack — header, payload and all —
	// exactly as it would have been written to the bulk OUT endpoint.
	WritePack(ctx context.Context, pack []byte) error

	// ReadTransfer returns one raw transfer, as the bulk IN endpoint would, or
	// an error wrapping ErrTimeout if nothing is available in time.
	ReadTransfer(timeout time.Duration) ([]byte, error)
}

// peerTransport is a Transport backed by a Peer.
type peerTransport struct {
	sender

	peer   Peer
	closed bool
}

// NewPeer returns a Transport that writes to and reads from p, with the same
// safety gate the USB transport uses.
//
// Close does not close p: the caller built the peer and owns its lifetime.
func NewPeer(p Peer, opts Options) Transport {
	t := &peerTransport{peer: p}
	t.sender = sender{opts: opts.withDefaults(), write: t.writePack}
	return t
}

func (t *peerTransport) writePack(ctx context.Context, o outbound) error {
	if t.closed {
		return errors.New("peer transport is closed")
	}
	return t.peer.WritePack(ctx, o.frame)
}

func (t *peerTransport) Recv(timeout time.Duration) ([]byte, error) {
	if t.closed {
		return nil, errors.New("peer transport is closed")
	}
	out, err := t.peer.ReadTransfer(t.resolveTimeout(timeout))
	if err != nil {
		return nil, err
	}
	t.opts.logf("transport: RX (peer) %d bytes: %s", len(out), dump(out))
	return out, nil
}

// Close marks the transport unusable. The peer itself is left alone.
func (t *peerTransport) Close() error {
	t.closed = true
	return nil
}
