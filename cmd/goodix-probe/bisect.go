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

// checkECResponsive sends the one command that is harmless, read-only and always
// answered by a healthy EC, and refuses to go on if nothing comes back. See
// errECUnresponsive for why the run stops here rather than carrying on.
//
// `0xa8` is the right probe: ClassSafe, no arguments that matter, and the first
// frame of every run from Run 5 to Run 11 — it has answered on this hardware
// eleven times. `0xae` deliberately is not, because it is the one command the EC
// still answers when it is stuck, so it cannot tell the two states apart.
func checkECResponsive(logger *log.Logger, tr transport.Transport, timeout time.Duration) error {
	st, ok := stepFor(opFirmwareVer)
	if !ok {
		return fmt.Errorf("no catalogue entry for firmware_version (0x%02x)", byte(opFirmwareVer))
	}

	logger.Printf("\n--- health check: %s (0x%02x) must answer before anything else is sent",
		opFirmwareVer.Name(), byte(opFirmwareVer))
	if err := tr.Send(opFirmwareVer, st.payload); err != nil {
		return fmt.Errorf("health check: send %s: %w", opFirmwareVer.Name(), err)
	}

	for range maxReadsPerStep {
		raw, err := tr.Recv(timeout)
		if errors.Is(err, transport.ErrTimeout) {
			break
		}
		if err != nil {
			return fmt.Errorf("health check: %w", err)
		}
		if len(raw) == 0 {
			logger.Printf("  empty transfer")
			continue
		}
		logger.Printf("  raw  %s", rawdump(raw))
		// Only an answer to 0xa8 itself counts. The EC emits 0x32 finger-detect
		// events on its own (Run 1), so "something arrived" would let a stuck
		// EC pass on a touch of the sensor.
		switch describe(logger, opFirmwareVer, raw) {
		case replyAck:
			// The version string follows the ACK as a second transfer. Read it
			// here, so the drain below does not report it as unsolicited.
			if err := collectFrom(logger, tr, opFirmwareVer, timeout, true); err != nil {
				return fmt.Errorf("health check: %w", err)
			}
		case replyData:
		default:
			continue
		}
		logger.Printf("  the EC is answering plaintext commands — the run may proceed")
		drain(logger, tr, timeout)
		return nil
	}

	logger.Printf("  no answer to %s.", opFirmwareVer.Name())
	return errECUnresponsive
}

// errECUnresponsive means the EC did not answer the harmless liveness probe, so
// it is not in the state a run assumes and nothing else should be sent to it.
//
// Run 12 (2026-09-20) is why this exists. That run started with the EC still
// inside the TLS handshake Run 11 had left unfinished, and in that state the EC
// answered no plaintext command at all except `0xae`: `0xa8`, which had returned
// the firmware string fifteen minutes earlier, drew nothing. The run sent the
// whole init anyway, into an EC that was acknowledging none of it, and the
// internal keyboard died at step 8. Talking to a part that is not listening is
// the shape of mistake that wedges this EC, so a run now stops before the first
// step instead of after the eighth.
var errECUnresponsive = errors.New("the EC did not answer firmware_version (0xa8), so it is not in the " +
	"state a run assumes, and nothing was sent. A working internal keyboard does not mean the EC is " +
	"clean — the host's i8042 recovers on its own, the EC does not. An unfinished --tls handshake " +
	"leaves it like this, and neither a reset (0xa2) nor, in Run 14, a cold power cycle cleared it. " +
	"What did (Run 16): shut down with the charger PLUGGED IN, hold the power button 40 s, then boot. Run again with --read-state to see which state it is in; " +
	"docs/protocol.md, \"Recovering the EC\", has the rest")

// healthMode says what runBisect asks the EC before the first step.
type healthMode int

const (
	// healthOff skips the check: a rehearsal has no EC to ask.
	healthOff healthMode = iota
	// healthCheck sends 0xa8 and stops the run if nothing answers.
	healthCheck
	// healthReadState is healthCheck, and when 0xa8 goes unanswered it sends
	// one 0xae to find out why (--read-state). The run still stops.
	healthReadState
)

// statusHandshakeOpen is the 0xae status bit Run 12 saw set, with the TLS bit
// clear, in the EC Run 11 had left inside an unfinished handshake. One
// observation: the name is a hypothesis, which is why proto does not own it.
const statusHandshakeOpen = 1 << 3

// run12Counter is the trailing counter of Run 12's 0xae reply. It had only ever
// risen since the Windows driver's one cold init, which restarted it at 0x02.
const run12Counter = 0x14

// readStuckState sends a single get_mcu_state (0xae) to an EC that has just
// ignored 0xa8, reports what the reply says about why, and checks the keyboard.
// It sends nothing else, whatever comes back.
//
// 0xae is the one frame worth sending into that EC: in Run 12 it was the only
// command the stuck EC answered, and the keyboard survived it. What it answers
// tells a failed cold power cycle (status 0x08, counter still counting up from
// 0x14) from an EC that did reset and is unhappy for a new reason — the two call
// for different next steps, and nothing else can tell them apart without
// sending more.
func readStuckState(logger *log.Logger, host bisectHost, tr transport.Transport, timeout, keyWait time.Duration) error {
	st, ok := stepFor(opMCUState)
	if !ok {
		return fmt.Errorf("no catalogue entry for get_mcu_state (0x%02x)", byte(opMCUState))
	}
	logger.Printf("\n--- --read-state: one %s (0x%02x), the only command the stuck EC answered in Run 12",
		opMCUState.Name(), byte(opMCUState))
	host.Mark("read-state: sending get_mcu_state")
	if err := tr.Send(opMCUState, st.payload); err != nil {
		return fmt.Errorf("read-state: send %s: %w", opMCUState.Name(), err)
	}

	var state *proto.MCUState
	for range maxReadsPerStep {
		raw, err := tr.Recv(timeout)
		if errors.Is(err, transport.ErrTimeout) {
			break
		}
		if err != nil {
			return fmt.Errorf("read-state: %w", err)
		}
		if len(raw) == 0 {
			logger.Printf("  empty transfer")
			continue
		}
		logger.Printf("  raw  %s", rawdump(raw))
		if describe(logger, opMCUState, raw) != replyData {
			continue
		}
		if s, err := mcuStateFrom(raw); err != nil {
			logger.Printf("  %v", err)
		} else {
			state = &s
		}
		break
	}
	drain(logger, tr, timeout)

	for _, line := range stuckVerdict(state) {
		logger.Printf("  %s", line)
	}
	return checkKeyboard(logger, host, "read-state", keyWait)
}

// mcuStateFrom decodes a raw 0xae transfer down to the MCU state.
func mcuStateFrom(raw []byte) (proto.MCUState, error) {
	_, packPayload, err := proto.DecodePack(raw)
	if err != nil {
		return proto.MCUState{}, err
	}
	_, msgPayload, err := proto.DecodeMessage(packPayload)
	if err != nil {
		return proto.MCUState{}, err
	}
	return proto.DecodeMCUState(msgPayload)
}

// stuckVerdict turns the 0xae reply of an EC that ignored 0xa8 into what it
// means and what to do next. A nil state means 0xae went unanswered too.
func stuckVerdict(s *proto.MCUState) []string {
	if s == nil {
		return []string{
			"VERDICT: the EC answers nothing, not even 0xae. That is worse than Run 12, where 0xae still",
			"answered. Send nothing more; the reset has to come from outside (docs/protocol.md, \"Recovering the EC\").",
		}
	}
	counter := s.Raw[len(s.Raw)-1]
	lines := []string{s.String(), fmt.Sprintf("trailing counter 0x%02x (Run 12: 0x%02x; the one real EC reset on record restarted it at 0x02)",
		counter, run12Counter)}
	switch {
	case s.Status&statusHandshakeOpen != 0 && !s.TLSConnected:
		lines = append(lines,
			"VERDICT: still Run 12's state — the handshake Run 11 left open. Whatever reset was tried did not",
			"reach the EC's RAM. A deeper reset is needed (docs/protocol.md, \"Recovering the EC\").")
	case counter < run12Counter:
		lines = append(lines,
			"VERDICT: the counter went DOWN, so the EC was reset, and it still ignores 0xa8. This is a new",
			"state, not the stuck handshake. Record the reply in docs/protocol.md before trying anything else.")
	default:
		lines = append(lines,
			"VERDICT: a status not seen in a stuck EC before. Record the reply in docs/protocol.md before",
			"trying anything else.")
	}
	return lines
}

// errBaseline means the internal keyboard did not respond before anything was
// done, so a bisect run would prove nothing.
var errBaseline = errors.New("internal keyboard not responding before the run")

// The opcodes above the safe ceiling that a bisect run can be told to send.
// Every one of them is a frame the Windows driver sends with a payload that is
// on record; none is destructive, and none could be, because the transport
// refuses a destructive opcode whatever the allowlist says.
const (
	opEnableChip     proto.Opcode = 0x96
	opFirmwareVer    proto.Opcode = 0xa8
	opMCUState       proto.Opcode = 0xae
	opGetImage       proto.Opcode = 0x20
	opFDTDown        proto.Opcode = 0x32
	opFDTUp          proto.Opcode = 0x34
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
	{opFDTDown, "allow-32", "bisect: let --wait-finger send fdt_down (0x32). Arms the EC to report a finger with one unsolicited event; the six thresholds are derived from the EC's own readings the way the vendor derives them (docs/protocol.md). Never a --steps entry. PLAN.md Phase 5d"},
	{opFDTUp, "allow-34", "bisect: let --wait-finger send fdt_up (0x34). Arms the EC to report the finger lifting; thresholds derived from the finger-down event, as the vendor does. Never a --steps entry. PLAN.md Phase 5d"},
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
		if fdtArm(op) {
			return nil, fmt.Errorf("opcode 0x%02x (%s) is not a step: its thresholds come from the EC's "+
				"previous readings, so only --wait-finger sends it (with --%s)", byte(op), op.Name(), mustUnlock(op).flag)
		}
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

// mustUnlock is unlockFor for an opcode known to be in the table.
func mustUnlock(op proto.Opcode) unlock {
	u, _ := unlockFor(op)
	return u
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
	ops []proto.Opcode, timeout, keyWait time.Duration, health healthMode,
	after func(transport.Transport) error) error {

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

	if health != healthOff {
		if err := checkECResponsive(logger, tr, timeout); err != nil {
			if errors.Is(err, errECUnresponsive) && health == healthReadState {
				if kerr := readStuckState(logger, host, tr, timeout, keyWait); kerr != nil {
					return kerr
				}
			}
			return err
		}
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

	// The Phase 5 frames are answered with an ACK in every one of the vendor
	// driver's nine complete inits, so a rehearsal that saw silence instead would
	// misrepresent the live run — collect would report "no ACK" for a command
	// that is in fact acknowledged.
	//
	// Be precise about what these are: the ACK is on record from the driver log,
	// the bytes below are OUR encoding of it rather than a capture, and the data
	// replies the log also records (0x98 and 0x90 answer `01 01`) are deliberately
	// not invented. 0x96 and 0xd0 get nothing: the log shows the driver not
	// waiting for a reply to 0x96, and 0xd0 being answered by a handshake.
	// 0x82 and 0xa6 are ClassSafe and need no flag, but they are in the same
	// position: acknowledged in the log and in Runs 9 and 10, data reply not
	// captured. 0xae is left out deliberately — it answers with NO ACK.
	for _, op := range []proto.Opcode{
		opReset, opIdle, opSetDAC, opUploadConfig, opTLSEstablished, opGetImage,
		0x82, 0xa6,
	} {
		if _, done := byCmd[op]; done {
			continue
		}
		st, ok := bisectable(op)
		if !ok {
			continue
		}
		byCmd[op] = transport.Exchange{Cmd: op, Payload: st.payload, Responses: [][]byte{
			proto.Encode(proto.AckCmd, []byte{byte(op), 0x01}),
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
