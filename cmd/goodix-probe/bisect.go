package main

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// Bisect mode answers the question Run 1 left open: which step stops the
// internal keyboard. The EC fails silently — in Run 1 the kernel logged nothing
// until something wrote to the i8042 half an hour later (FINDINGS.md) — so the
// only reliable signal is a human pressing a key on the internal keyboard after
// every step. The run stops at the first step that is not followed by one.
//
// Step 0 ("attach") opens and claims the USB interface and only reads, sending
// nothing, so a wedge caused by attaching alone is told apart from one caused
// by a command.

// bisectHost is the machine around the probe: everything bisect observes that
// is not the sensor itself.
type bisectHost interface {
	// WaitKey reports whether a key was pressed on the internal keyboard within
	// timeout. Presses made before the call do not count.
	WaitKey(timeout time.Duration) (bool, error)
	// SensorPresent reports whether 27c6:5120 is still enumerated.
	SensorPresent() bool
	// Snapshot returns counters worth logging around each step, such as the
	// i8042 interrupt counts.
	Snapshot() string
	// Mark writes a marker to the kernel log, so the steps line up with
	// kernel messages in `journalctl -k`.
	Mark(msg string)
}

// errKeyboardLost means the internal keyboard did not respond after a step.
var errKeyboardLost = errors.New("internal keyboard stopped responding")

// errBaseline means the internal keyboard did not respond before anything was
// done, so a bisect run would prove nothing.
var errBaseline = errors.New("internal keyboard not responding before the run")

// opPSKRead is preset_psk_read. It wedged the EC in Run 1 and Run 2, so it is
// not a probe step. --allow-e4 admits it to a bisect run, and only there, to
// confirm that it wedges the EC on its own (docs/bisect-runbook.md).
const opPSKRead proto.Opcode = 0xe4

const pskReadPurpose = "wedged the EC in Runs 1 and 2; expect an ACK, then a dead keyboard"

// parseSteps turns a comma-separated opcode list (hex, e.g. "00,a8") into
// steps. Only opcodes in the default steps list are accepted, so bisect can
// never send something the probe itself would not. The one exception is
// preset_psk_read, accepted only when allowE4 is set.
func parseSteps(list string, allowE4 bool) ([]proto.Opcode, error) {
	var out []proto.Opcode
	for field := range strings.SplitSeq(list, ",") {
		field = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(field)), "0x")
		if field == "" {
			continue
		}
		v, err := strconv.ParseUint(field, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("bad opcode %q: %w", field, err)
		}
		op := proto.Opcode(v)
		if op == opPSKRead && !allowE4 {
			return nil, fmt.Errorf("opcode 0xe4 wedges the EC; it needs --allow-e4 (see docs/bisect-runbook.md)")
		}
		if purpose(op) == "" {
			return nil, fmt.Errorf("opcode 0x%02x is not in the probe's step list", byte(op))
		}
		out = append(out, op)
	}
	return out, nil
}

// purpose returns the step description of op, or "" if op is neither a step
// nor preset_psk_read.
func purpose(op proto.Opcode) string {
	if op == opPSKRead {
		return pskReadPurpose
	}
	for _, s := range steps {
		if s.cmd == op {
			return s.purpose
		}
	}
	return ""
}

// defaultBisectSteps is every probe step, in order.
func defaultBisectSteps() string {
	var parts []string
	for _, s := range steps {
		parts = append(parts, fmt.Sprintf("%02x", byte(s.cmd)))
	}
	return strings.Join(parts, ",")
}

// runBisect runs attach and then each opcode, draining the device and checking
// the internal keyboard after every one. It returns errKeyboardLost at the
// first step the keyboard does not survive.
func runBisect(logger *log.Logger, host bisectHost, open func() (transport.Transport, error),
	ops []proto.Opcode, timeout, keyWait time.Duration) error {

	logger.Printf("bisect: attach, then %d command(s); keyboard check after each step", len(ops))
	logger.Printf("bisect: press a harmless key (Shift) on the INTERNAL keyboard when asked")

	logger.Printf("\n--- baseline")
	if err := checkKeyboard(logger, host, "baseline", keyWait); err != nil {
		if errors.Is(err, errKeyboardLost) {
			return errBaseline
		}
		return err
	}

	logger.Printf("\n--- step 0: attach (open + claim, read only, send nothing)")
	host.Mark("step 0 attach: opening device")
	tr, err := open()
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer tr.Close()
	drain(logger, tr, timeout)
	if err := checkKeyboard(logger, host, "step 0 attach", keyWait); err != nil {
		return err
	}

	for i, op := range ops {
		name := op.Name()
		label := fmt.Sprintf("step %d %s (0x%02x)", i+1, name, byte(op))
		logger.Printf("\n--- %s — %s", label, purpose(op))
		host.Mark(label + ": sending")

		if err := tr.Send(op, nil); err != nil {
			return fmt.Errorf("send %s: %w", name, err)
		}
		if err := collect(logger, tr, op, timeout); err != nil {
			return fmt.Errorf("recv after %s: %w", name, err)
		}
		drain(logger, tr, timeout)
		if err := checkKeyboard(logger, host, label, keyWait); err != nil {
			return err
		}
	}

	logger.Printf("\nRESULT: internal keyboard alive after every step")
	host.Mark("bisect done: keyboard alive after every step")
	return nil
}

// checkKeyboard logs the host state and waits for a key press on the internal
// keyboard.
func checkKeyboard(logger *log.Logger, host bisectHost, after string, keyWait time.Duration) error {
	logger.Printf("  host: %s, sensor enumerated: %t", host.Snapshot(), host.SensorPresent())
	logger.Printf("  >>> press Shift on the INTERNAL keyboard (waiting %s)", keyWait)

	ok, err := host.WaitKey(keyWait)
	if err != nil {
		return fmt.Errorf("keyboard check after %s: %w", after, err)
	}
	if !ok {
		logger.Printf("  RESULT: no key press within %s after %s", keyWait, after)
		logger.Printf("  host: %s, sensor enumerated: %t", host.Snapshot(), host.SensorPresent())
		host.Mark("NO KEY after " + after)
		return fmt.Errorf("%w after %s", errKeyboardLost, after)
	}
	logger.Printf("  keyboard alive after %s", after)
	host.Mark("keyboard alive after " + after)
	return nil
}

// scriptFor returns the Run 1 exchanges for ops, in the order given, so
// --bisect --replay accepts any --steps selection. preset_psk_read gets the
// ACK that Runs 1 and 2 both saw; nothing came after it.
func scriptFor(ops []proto.Opcode) []transport.Exchange {
	byCmd := map[proto.Opcode]transport.Exchange{
		opPSKRead: {Cmd: opPSKRead, Responses: [][]byte{
			// ACK for preset_psk_read, status 01.
			{0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xe4, 0x01, 0x12},
		}},
	}
	for _, ex := range run1Script() {
		byCmd[ex.Cmd] = ex
	}
	out := make([]transport.Exchange, 0, len(ops))
	for _, op := range ops {
		ex, ok := byCmd[op]
		if !ok {
			ex = transport.Exchange{Cmd: op}
		}
		out = append(out, ex)
	}
	return out
}
