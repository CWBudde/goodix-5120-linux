package main

import (
	"errors"
	"fmt"
	"log"
	"slices"
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

// The opcodes above the safe ceiling that a bisect run can be told to send.
// Every one of them is a frame the Windows driver sends with a payload that is
// on record; none is destructive, and none could be, because the transport
// refuses a destructive opcode whatever the allowlist says.
const (
	opEnableChip     proto.Opcode = 0x96
	opGetImage       proto.Opcode = 0x20
	opIdle           proto.Opcode = 0x70
	opPSKRead        proto.Opcode = 0xe4
	opRequestTLS     proto.Opcode = 0xd0
	opReset          proto.Opcode = 0xa2
	opSetDAC         proto.Opcode = 0x98
	opTLSEstablished proto.Opcode = 0xd4
	opUploadConfig   proto.Opcode = 0x90
)

// unlock is one above-ceiling opcode together with the flag that admits it and
// the help text that flag carries.
//
// One flag per opcode is deliberate friction, and it is why this is a table of
// hand-written entries rather than a list generated from the catalogue: the
// reason a command is safe enough to try, and what it does to the device, is
// something a person has to have written down. The flags are still *registered*
// from this table, so adding an opcode cannot mean forgetting the flag.
type unlock struct {
	op   proto.Opcode
	flag string
	help string
}

// unlockable is the complete set. TestEveryAboveCeilingVendorFrameIsCatalogued
// pins it against the vendor catalogue in both directions, so a new
// state-changing frame cannot appear with no flag and no explanation.
var unlockable = []unlock{
	{opEnableChip, "allow-96", "bisect: also accept enable_chip (0x96) in --steps. The vendor's FIRST frame on every init, payload 01 02; the driver does not wait for a reply. State-changing"},
	{opPSKRead, "allow-e4", "bisect: also accept preset_psk_read (0xe4) in --steps. Sent with the vendor's 8-byte payload; the EMPTY form wedged the EC in Runs 1, 2 and 4 and is now refused outright (see docs/bisect-runbook.md). Its reply contains a hash of the device PSK — keep it out of the repo"},
	{opReset, "allow-a2", "bisect: also accept reset (0xa2) in --steps. State-changing; the vendor sends it before reading the chip ID, which without it reads a pre-reset value (Run 9). Sent with the vendor payload 01 14 (see docs/bisect-runbook.md)"},
	{opIdle, "allow-70", "bisect: also accept mcu_switch_to_idle_mode (0x70) in --steps. Payload 14 00; the vendor's frame 9, the first of the three config frames that precede the TLS request (PLAN.md Phase 5a)"},
	{opSetDAC, "allow-98", "bisect: also accept set_dac (0x98) in --steps. Payload c8 0b be 00 bc 00 bc 00 — DAC values the vendor derives from THIS machine's OTP, so they are specific to this sensor (PLAN.md Phase 5a)"},
	{opUploadConfig, "allow-90", "bisect: also accept upload_config_mcu (0x90) in --steps. Writes the vendor's 224-byte register script into the sensor MCU. It writes no flash, but it is the largest state change in the init — promote it on a run of its own (PLAN.md Phase 5a)"},
	{opRequestTLS, "allow-d0", "bisect: also accept request_tls_connection (0xd0). Payload 00 00; answered with NO ACK — the EC then opens a TLS handshake as the client. With --tls the bridge sends this itself, so leave it out of --steps"},
	{opTLSEstablished, "allow-d4", "bisect: also accept tls_successfully_established (0xd4). Payload 00 00; the vendor sends it right after the handshake completes. With --tls the bridge sends it on success"},
	{opGetImage, "allow-20", "bisect: also accept mcu_get_image (0x20). Payload 01 00; asks the EC for one frame, which arrives as an encrypted TLS record. Needed by --capture (PLAN.md Phase 5c)"},
}

// unlockFor returns the catalogue entry for op.
func unlockFor(op proto.Opcode) (unlock, bool) {
	for _, u := range unlockable {
		if u.op == op {
			return u, true
		}
	}
	return unlock{}, false
}

// parseSteps turns a comma-separated opcode list (hex, e.g. "a8,ae") into steps.
// An opcode is accepted only if it is in the vendor catalogue, so its payload is
// on record. A ClassSafe opcode passes on its own; an opcode above the ceiling
// (preset_psk_read, reset) passes only when named in allow — the set the
// matching --allow-… flag turns on. Bisect therefore cannot send a frame the
// vendor driver has never been observed to send, and cannot get above the
// ceiling except for an opcode the operator has explicitly unlocked.
func parseSteps(list string, allow ...proto.Opcode) ([]proto.Opcode, error) {
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
		if _, ok := stepFor(op); !ok {
			return nil, fmt.Errorf("opcode 0x%02x is not a safe command with a known vendor payload", byte(op))
		}
		if class, ok := op.Class(); ok && class != proto.ClassSafe && !slices.Contains(allow, op) {
			return nil, needsAllow(op)
		}
		out = append(out, op)
	}
	return out, nil
}

// needsAllow explains that op is above the safe ceiling and names the flag that
// admits it.
func needsAllow(op proto.Opcode) error {
	u, ok := unlockFor(op)
	if !ok {
		return fmt.Errorf("opcode 0x%02x is above the safe ceiling and cannot be sent by bisect", byte(op))
	}
	class, _ := op.Class()
	return fmt.Errorf("opcode 0x%02x (%s) is %s; it needs --%s (see docs/bisect-runbook.md)",
		byte(op), op.Name(), class, u.flag)
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
//
// after, when non-nil, runs once every step has passed and is followed by one
// more keyboard check. That is where --tls hangs its TLS bridge: it needs the
// device in the state the steps left it in, and it needs the same keyboard
// safety net as a step.
func runBisect(logger *log.Logger, host bisectHost, open func() (transport.Transport, error),
	ops []proto.Opcode, timeout, keyWait time.Duration, after func(transport.Transport) error) error {

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
		st, ok := stepFor(op)
		if !ok {
			return fmt.Errorf("step %d: opcode 0x%02x has no catalogue entry", i+1, byte(op))
		}
		label := fmt.Sprintf("step %d %s (0x%02x)", i+1, name, byte(op))
		logger.Printf("\n--- %s — %s", label, st.purpose)
		host.Mark(label + ": sending")

		if err := tr.Send(op, st.payload); err != nil {
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

	if after != nil {
		host.Mark("after-steps hook: starting")
		if err := after(tr); err != nil {
			// The hook's own failure is not a keyboard failure, and the keyboard
			// is worth checking either way: whatever it just did to the device is
			// exactly the kind of thing that wedges the EC.
			logger.Printf("\n  after the steps: %v", err)
			if kerr := checkKeyboard(logger, host, "the after-steps hook", keyWait); kerr != nil {
				return kerr
			}
			return err
		}
		if err := checkKeyboard(logger, host, "the after-steps hook", keyWait); err != nil {
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

// scriptFor returns the replay exchanges for ops, in the order given, so
// --bisect --replay accepts any --steps selection.
//
// Every exchange asserts the outbound payload as well as the opcode, so a
// rehearsal fails if the probe sends something other than the vendor's bytes.
// preset_psk_read gets the ACK that Runs 1, 2 and 4 all saw. Nothing came after
// it on this device — but those runs sent the empty frame, and what goes out
// now is the vendor's, which the driver log shows is answered with 41 more
// bytes. The rehearsal deliberately does not invent them.
func scriptFor(ops []proto.Opcode) []transport.Exchange {
	byCmd := map[proto.Opcode]transport.Exchange{}
	for _, ex := range run1Script() {
		byCmd[ex.Cmd] = ex
	}
	if st, ok := bisectable(opPSKRead); ok {
		byCmd[opPSKRead] = transport.Exchange{Cmd: opPSKRead, Payload: st.payload, Responses: [][]byte{
			// ACK for preset_psk_read, status 01.
			{0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xe4, 0x01, 0x12},
		}}
	}

	out := make([]transport.Exchange, 0, len(ops))
	for _, op := range ops {
		ex, ok := byCmd[op]
		if !ok {
			st, _ := stepFor(op)
			ex = transport.Exchange{Cmd: op, Payload: st.payload}
		}
		out = append(out, ex)
	}
	return out
}
