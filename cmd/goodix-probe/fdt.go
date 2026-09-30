package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/session"
	"goodix5120/internal/transport"
)

// --wait-finger is PLAN.md Phase 5d: instead of asking for a frame at once, arm
// the EC's finger detection, take the frame when the EC reports a finger, then
// arm finger-up and wait for the lift. It is the vendor's capture loop, once
// round (docs/protocol.md, "Capture loop"):
//
//	TX 32 arm down → ACK … RX 32 event on touch
//	TX 20 get image → ACK, RX b0 (the TLS image record)
//	TX 34 arm up   → ACK … RX 34 event on lift
//
// The thresholds in each arm are derived from the EC's previous readings with
// proto.DownThresholds and proto.UpThresholds, rules that reproduce every
// derived arm in dump.pcapng. The first down arm starts from the vendor's own
// arm in the catalogue; if those thresholds no longer fit, the EC answers
// "base invalid" with its current readings, and the arm is repeated from those,
// which is what the vendor driver does.

// maxBaseRearms bounds the base-invalid loop. The vendor needed one re-arm
// each of the five times it happened in dump.pcapng.
const maxBaseRearms = 3

// fdtPoll is how long one Recv waits while waiting for a finger. Short, so the
// wait can be bounded by a deadline rather than by the transport's timeout.
const fdtPoll = time.Second

// fdtArm reports whether op is a finger-detect arm, which --steps may not name.
func fdtArm(op proto.Opcode) bool { return op == opFDTDown || op == opFDTUp }

// captureOnTouch runs the loop above and writes the frame to path.
func captureOnTouch(ctx context.Context, logger *log.Logger, tr transport.Transport,
	bridge *session.Bridge, cfg tlsConfig, rehearsal *session.LoopbackEC) error {

	logger.Printf("\n--- finger detection (PLAN.md Phase 5d)")
	start, ok := stepFor(opFDTDown)
	if !ok {
		return fmt.Errorf("no catalogue entry for fdt_down (0x%02x)", byte(opFDTDown))
	}
	vendorArm, err := proto.DecodeFDTArm(opFDTDown, start.payload)
	if err != nil {
		return fmt.Errorf("the catalogued fdt_down arm does not decode: %w", err)
	}
	thresholds := vendorArm.Thresholds
	logger.Printf("  starting from the vendor's thresholds %x (%s)", thresholds, start.note)

	var down proto.FDTEvent
	for attempt := 0; ; attempt++ {
		if err := sendFDTArm(logger, tr, opFDTDown, proto.FDTArm{
			Thresholds: thresholds,
			Timestamp:  uint16(time.Now().UnixMilli()),
		}); err != nil {
			return err
		}
		if rehearsal != nil {
			rehearseDownEvent(logger, rehearsal, attempt)
		}
		if attempt == 0 {
			logger.Printf("  >>> TOUCH THE SENSOR now; waiting up to %s", cfg.fingerTimeout)
		}
		ev, err := waitFDTEvent(ctx, logger, tr, opFDTDown, cfg.fingerTimeout)
		if err != nil {
			return err
		}
		switch ev.Kind {
		case proto.FDTEventDown:
			down = ev
		case proto.FDTEventBaseInvalid:
			if attempt >= maxBaseRearms {
				return fmt.Errorf("the EC reported base invalid %d times in a row; record the readings above in docs/protocol.md", attempt+1)
			}
			thresholds = proto.DownThresholds(ev.Zones)
			logger.Printf("  base invalid: the EC sent its current readings; re-arming with %x, as the vendor does", thresholds)
			continue
		default:
			return fmt.Errorf("unexpected finger-detect event %s; record it in docs/protocol.md", ev)
		}
		break
	}
	logger.Printf("  finger down, zones touched 0x%02x", down.Flags)

	if err := captureFrame(ctx, logger, tr, bridge, cfg.capture, rehearsal); err != nil {
		return err
	}

	up := proto.FDTArm{Thresholds: proto.UpThresholds(down, proto.FDTDeltaObserved)}
	if err := sendFDTArm(logger, tr, opFDTUp, up); err != nil {
		return err
	}
	if rehearsal != nil {
		rehearseUpEvent(logger, rehearsal)
	}
	logger.Printf("  >>> LIFT THE FINGER now; waiting up to %s", cfg.fingerTimeout)
	ev, err := waitFDTEvent(ctx, logger, tr, opFDTUp, cfg.fingerTimeout)
	if errors.Is(err, errNoFinger) {
		// Not a failure of the capture, which is already written. The EC stays
		// armed for the lift; the drain collects the event if it comes late.
		logger.Printf("  no finger-up event in %s; the EC is left armed for it, which is also where the vendor leaves it", cfg.fingerTimeout)
		return nil
	}
	if err != nil {
		return err
	}
	if ev.Kind != proto.FDTEventUp {
		return fmt.Errorf("unexpected finger-detect event %s after arming finger-up; record it in docs/protocol.md", ev)
	}
	logger.Printf("  finger up; the next down arm would use %x", proto.DownThresholds(ev.Zones))
	return nil
}

// sendFDTArm encodes and sends one arm. Its ACK is read by waitFDTEvent, which
// has to read past it to the event anyway.
func sendFDTArm(logger *log.Logger, tr transport.Transport, op proto.Opcode, arm proto.FDTArm) error {
	payload, err := proto.EncodeFDTArm(op, arm)
	if err != nil {
		return err
	}
	st, _ := stepFor(op)
	logger.Printf("  sending %s (0x%02x) — %s, thresholds %x", op.Name(), byte(op), st.purpose, arm.Thresholds)
	if err := tr.Send(op, payload); err != nil {
		return fmt.Errorf("send %s: %w", op.Name(), err)
	}
	return nil
}

// errNoFinger means nothing happened on the sensor before the deadline.
var errNoFinger = errors.New("no finger-detect event before the deadline")

// waitFDTEvent reads until an event for op arrives or wait runs out. The arm's
// ACK is logged on the way past, as is anything else that arrives; an
// finger-detect event is not something to drop because it came at an odd time.
func waitFDTEvent(ctx context.Context, logger *log.Logger, tr transport.Transport,
	op proto.Opcode, wait time.Duration) (proto.FDTEvent, error) {

	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return proto.FDTEvent{}, err
		}
		raw, err := tr.Recv(min(fdtPoll, time.Until(deadline)))
		if errors.Is(err, transport.ErrTimeout) {
			continue
		}
		if err != nil {
			return proto.FDTEvent{}, err
		}
		if len(raw) == 0 {
			continue
		}
		logger.Printf("  raw  %s", hexdump(raw))

		flags, body, err := proto.DecodePack(raw)
		if err != nil || flags != proto.FlagMessage {
			logger.Printf("  not a message pack (flags 0x%02x, %v); still waiting", flags, err)
			continue
		}
		cmd, payload, err := proto.DecodeMessage(body)
		if err != nil {
			logger.Printf("  undecodable message (%v); still waiting", err)
			continue
		}
		if cmd == proto.AckCmd {
			acked, status, err := proto.DecodeAck(cmd, payload)
			if err == nil {
				logger.Printf("  ACK for 0x%02x, status 0x%02x", byte(acked), status)
			}
			continue
		}
		if cmd != op {
			logger.Printf("  unexpected 0x%02x message while waiting for 0x%02x; still waiting", byte(cmd), byte(op))
			continue
		}
		ev, err := proto.DecodeFDTEvent(cmd, payload)
		if err != nil {
			return proto.FDTEvent{}, err
		}
		logger.Printf("  %s", ev)
		return ev, nil
	}
	return proto.FDTEvent{}, fmt.Errorf("waiting for 0x%02x: %w", byte(op), errNoFinger)
}

// The rehearsal's finger. These are events from dump.pcapng (frames 131, 29
// and 26): capacitance readings of six zones, no image. The first arm is
// answered "base invalid" so the rehearsal also walks the re-arm path.
var (
	rehearsalBaseInvalid = []byte{0x80, 0x00, 0x00, 0x00, 0x71, 0x01, 0x8c, 0x01, 0x56, 0x01, 0x72, 0x01, 0x54, 0x01, 0x72, 0x01}
	rehearsalDown        = []byte{0x02, 0x00, 0x2f, 0x00, 0xd1, 0x00, 0x0d, 0x01, 0xb5, 0x00, 0x05, 0x01, 0x3f, 0x01, 0x1c, 0x01}
	rehearsalUp          = []byte{0x00, 0x02, 0x00, 0x00, 0x70, 0x01, 0x8b, 0x01, 0x57, 0x01, 0x73, 0x01, 0x54, 0x01, 0x72, 0x01}
)

func rehearseDownEvent(logger *log.Logger, ec *session.LoopbackEC, attempt int) {
	if attempt == 0 {
		logger.Printf("  rehearsal: the stand-in answers the first arm with a captured base-invalid event")
		ec.SendEvent(opFDTDown, rehearsalBaseInvalid)
		return
	}
	logger.Printf("  rehearsal: the stand-in sends a captured finger-down event (zone 4 uncovered)")
	ec.SendEvent(opFDTDown, rehearsalDown)
}

func rehearseUpEvent(logger *log.Logger, ec *session.LoopbackEC) {
	logger.Printf("  rehearsal: the stand-in sends a captured finger-up event")
	ec.SendEvent(opFDTUp, rehearsalUp)
}
