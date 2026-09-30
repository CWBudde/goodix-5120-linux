package main

import (
	"bytes"
	"context"
	"errors"
	"log"
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
