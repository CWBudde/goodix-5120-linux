// Command goodix-probe performs read-only interrogation of a Goodix 27c6:5120
// fingerprint sensor over USB bulk transfers.
//
// It exists to answer one question: does this USB-attached 5120 speak the same
// command set as the 51x0 (MILAN_ST411SEC) family that upstream reverse
// engineered for the 5110? A plausible firmware version string means yes.
//
// The probe is read-only by construction. It sends only opcodes classified
// ClassSafe, and the transport refuses anything above that ceiling before a
// byte reaches the device. Firmware-write opcodes are not compiled into this
// binary at all. See the README for the full safety model.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// maxReadsPerStep bounds the receive loop for one command: an ACK, a data
// message and the odd unsolicited message. Anything beyond it is left to the
// final drain.
const maxReadsPerStep = 4

// maxDrainReads bounds the final drain, so a device that never goes quiet
// cannot hold the probe forever.
const maxDrainReads = 8

func main() {
	var (
		dryRun  = flag.Bool("dry-run", false, "decode and print the frames that would be sent, then exit without opening any USB device")
		replay  = flag.Bool("replay", false, "run against the built-in replay fake instead of real hardware")
		verbose = flag.Bool("v", false, "log every transfer as hex")
		timeout = flag.Duration("timeout", 5*time.Second, "per-transfer timeout")

		bisect     = flag.Bool("bisect", false, "attach, then one command per step, checking the internal keyboard after each (see docs/bisect-runbook.md)")
		stepList   = flag.String("steps", defaultBisectSteps(), "bisect: comma-separated hex opcodes to send after attach, in order")
		logPath    = flag.String("log", "", "bisect: log file, flushed after every line (default goodix-bisect-<time>.log)")
		keyWait    = flag.Duration("key-wait", 30*time.Second, "bisect: how long to wait for a key press on the internal keyboard")
		assumeKeys = flag.Bool("assume-keys", false, "bisect with --replay: skip the keyboard checks (no root needed)")
		allowE4    = flag.Bool("allow-e4", false, "bisect: also accept preset_psk_read (0xe4) in --steps. Sent with the vendor's 8-byte payload; the EMPTY form wedged the EC in Runs 1, 2 and 4 and is now refused outright (see docs/bisect-runbook.md)")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)

	if *allowE4 && !*bisect {
		logger.Print("--allow-e4 only works with --bisect")
		os.Exit(1)
	}

	if *dryRun {
		dryRunFrames(logger)
		return
	}

	if *bisect {
		os.Exit(mainBisect(*replay, *assumeKeys, *allowE4, *stepList, *logPath, *timeout, *keyWait))
	}

	opts := transport.Options{
		Ceiling: proto.ClassSafe, // never raised by this binary
		Timeout: *timeout,
		Verbose: *verbose,
		Logger:  logger,
	}

	var tr transport.Transport
	if *replay {
		tr = transport.NewReplay(run1Script(), opts)
	} else {
		opened, err := transport.OpenUSB(opts)
		if err != nil {
			logger.Printf("cannot open device: %v", err)
			explainOpenError(logger, err)
			os.Exit(1)
		}
		tr = opened
	}
	defer tr.Close()

	if err := run(logger, tr, *timeout); err != nil {
		logger.Printf("probe failed: %v", err)
		os.Exit(1)
	}
}

// mainBisect runs bisect mode and returns the exit status: 0 if the keyboard
// survived every step, 2 if it stopped (or was not working to begin with), 1
// on any other failure.
func mainBisect(replay, assumeKeys, allowE4 bool, stepList, logPath string, timeout, keyWait time.Duration) int {
	stderr := log.New(os.Stderr, "", 0)
	if assumeKeys && !replay {
		stderr.Print(errAssumeKeysLive)
		return 1
	}
	ops, err := parseSteps(stepList, allowE4)
	if err != nil {
		stderr.Printf("--steps: %v", err)
		return 1
	}

	if logPath == "" {
		logPath = "goodix-bisect-" + time.Now().Format("20060102-150405") + ".log"
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		stderr.Printf("cannot open log: %v", err)
		return 1
	}
	defer f.Close()
	logger := log.New(io.MultiWriter(os.Stdout, syncWriter{f}), "", log.Ltime|log.Lmicroseconds)

	var host bisectHost = assumeKeysHost{}
	if !assumeKeys {
		lh, err := newLinuxHost(!replay)
		if err != nil {
			logger.Printf("cannot watch the internal keyboard: %v", err)
			return 1
		}
		host = lh
	}

	opts := transport.Options{
		Ceiling: proto.ClassSafe, // never raised by this binary
		Timeout: timeout,
		Verbose: true, // the raw bytes are the point of a bisect run
		Logger:  logger,
	}
	allowed := "none"
	if slices.Contains(ops, opPSKRead) {
		// The one exception above the ceiling, and only when it is a step.
		opts.Allow = []proto.Opcode{opPSKRead}
		allowed = "preset_psk_read (0xe4)"
	}
	open := func() (transport.Transport, error) {
		if replay {
			return transport.NewReplay(scriptFor(ops), opts), nil
		}
		return transport.OpenUSB(opts)
	}

	mode := "LIVE HARDWARE"
	if replay {
		mode = "replay (no USB)"
	}
	logger.Printf("goodix-probe bisect — %s, ceiling=%s, allowed above it: %s, steps=%s, log=%s",
		mode, proto.ClassSafe, allowed, stepList, logPath)

	err = runBisect(logger, host, open, ops, timeout, keyWait)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errKeyboardLost), errors.Is(err, errBaseline):
		logger.Printf("\nstopped: %v", err)
		if errors.Is(err, errKeyboardLost) {
			logger.Printf("recover with a cold power cycle: shut down, unplug the charger, hold power ~30 s")
		}
		return 2
	default:
		logger.Printf("\nbisect failed: %v", err)
		if errors.Is(err, transport.ErrPermission) || errors.Is(err, transport.ErrNotFound) {
			explainOpenError(logger, err)
		}
		return 1
	}
}

func run(logger *log.Logger, tr transport.Transport, timeout time.Duration) error {
	logger.Printf("probing Goodix 27c6:5120 — read-only, ceiling=%s\n", proto.ClassSafe)

	for _, step := range steps {
		name := step.cmd.Name()
		if name == "" {
			name = "<unregistered>"
		}
		logger.Printf("\n--- %s (0x%02x) — %s", name, byte(step.cmd), step.purpose)

		if err := tr.Send(step.cmd, step.payload); err != nil {
			return fmt.Errorf("send %s: %w", name, err)
		}
		if err := collect(logger, tr, step.cmd, timeout); err != nil {
			return fmt.Errorf("recv after %s: %w", name, err)
		}
	}

	drain(logger, tr, timeout)

	logger.Printf("\ndone. Record anything notable in docs/protocol.md under \"Observed exchanges\".")
	return nil
}

// collect reads the responses to one command. The device answers with an ACK
// and then a separate data message, so it keeps reading until the data message
// arrives, the device goes quiet, or maxReadsPerStep is reached. Run 1 read
// once per command and so ran one transfer behind.
func collect(logger *log.Logger, tr transport.Transport, sent proto.Opcode, timeout time.Duration) error {
	acked := false
	for range maxReadsPerStep {
		raw, err := tr.Recv(timeout)
		if errors.Is(err, transport.ErrTimeout) {
			if acked {
				logger.Printf("  device went quiet after the ACK — no data message")
			} else {
				logger.Printf("  device went quiet — no ACK")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			logger.Printf("  empty transfer")
			continue
		}

		logger.Printf("  raw  %s", hexdump(raw))
		switch describe(logger, sent, raw) {
		case replyAck:
			acked = true
		case replyData:
			return nil
		}
	}
	logger.Printf("  stopped after %d reads; the drain will collect anything left", maxReadsPerStep)
	return nil
}

// drain reads until the device goes quiet, so the probe never exits with a
// response left queued in the EC. Run 1 did exit that way; whether it
// contributed to the wedge is unknown (FINDINGS.md), so this is hygiene, not a
// safety guarantee.
func drain(logger *log.Logger, tr transport.Transport, timeout time.Duration) {
	logger.Printf("\n--- drain")
	for i := range maxDrainReads {
		raw, err := tr.Recv(timeout)
		if errors.Is(err, transport.ErrTimeout) {
			logger.Printf("  device quiet after %d leftover transfer(s)", i)
			return
		}
		if err != nil {
			logger.Printf("  drain stopped: %v", err)
			return
		}
		logger.Printf("  leftover raw  %s", hexdump(raw))
		if len(raw) > 0 {
			describe(logger, 0, raw)
		}
	}
	logger.Printf("  device still sending after %d reads; giving up", maxDrainReads)
}

// reply classifies one received transfer relative to the command just sent.
type reply int

const (
	replyOther reply = iota // undecodable, unsolicited, or for another command
	replyAck                // the ACK for the command just sent
	replyData               // the data message for the command just sent
)

// describe decodes a response as far as it can, reporting honestly at the point
// it stops making sense rather than inventing structure.
func describe(logger *log.Logger, sent proto.Opcode, raw []byte) reply {
	flags, packPayload, err := proto.DecodePack(raw)
	if err != nil {
		logger.Printf("  outer frame did not decode: %v", err)
		logger.Printf("  (this is itself informative — the 5120 may not use 51x0 framing)")
		return replyOther
	}
	logger.Printf("  pack flags=0x%02x payload=%d bytes", flags, len(packPayload))

	cmd, msgPayload, err := proto.DecodeMessage(packPayload)
	if err != nil {
		logger.Printf("  inner message did not decode: %v", err)
		return replyOther
	}

	if cmd == proto.AckCmd {
		acked, status, err := proto.DecodeAck(cmd, msgPayload)
		switch {
		case err != nil:
			logger.Printf("  malformed ACK: %v", err)
			return replyOther
		case acked == sent:
			logger.Printf("  ACK for %s (0x%02x), status 0x%02x", acked.Name(), byte(acked), status)
			return replyAck
		default:
			logger.Printf("  stray ACK for 0x%02x (%s), status 0x%02x", byte(acked), acked.Name(), status)
			return replyOther
		}
	}

	kind := replyData
	if cmd == sent {
		logger.Printf("  data for %s (0x%02x)", cmd.Name(), byte(cmd))
	} else {
		kind = replyOther
		logger.Printf("  unsolicited message cmd=0x%02x (%s)", byte(cmd), cmd.Name())
	}
	if len(msgPayload) > 0 {
		logger.Printf("  payload %s", hexdump(msgPayload))
		if s := printable(msgPayload); s != "" {
			logger.Printf("  as text %q", s)
		}
	}
	return kind
}

func dryRunFrames(logger *log.Logger) {
	logger.Printf("dry run — no USB device is opened, nothing is transmitted\n")

	logger.Printf("\n=== what the probe would send ===")
	for _, st := range steps {
		printFrame(logger, "", st)
	}
	logger.Printf("\n%d frame(s). Verify the framing by hand against docs/protocol.md before running live.", len(steps))

	// The vendor sequence is reference material, not a plan. Printing it is how
	// the PLAN.md Phase 4 gate — "each planned command matches the vendor
	// sequence byte for byte" — actually gets checked by a human.
	logger.Printf("\n\n=== the Windows driver's init sequence, for reference ===")
	logger.Printf("transcribed from the vendor ETW log (docs/protocol.md). The probe sends NONE of this.")
	for i, st := range vendorInit {
		printFrame(logger, fmt.Sprintf("#%d ", i+1), st)
	}
}

// printFrame renders one catalogue entry: its class, its payload rule and the
// exact bytes that would go on the wire.
func printFrame(logger *log.Logger, prefix string, st step) {
	name := st.cmd.Name()
	if name == "" {
		name = "<unregistered>"
	}

	status := "UNREGISTERED — would be refused"
	if class, ok := st.cmd.Class(); ok {
		status = class.String()
	}
	if rule, ok := st.cmd.PayloadRule(); ok {
		status += ", " + rule.String()
	}

	logger.Printf("\n%s%s (0x%02x) [%s]\n  %s", prefix, name, byte(st.cmd), status, st.purpose)
	if st.note != "" {
		logger.Printf("  note: %s", st.note)
	}
	if !st.known() {
		logger.Printf("  payload not on record — no frame can be built")
		return
	}
	logger.Printf("  %s", hexdump(proto.Encode(st.cmd, st.payload)))
}

// run1Script replays the transfers captured in Run 1 (docs/protocol.md), so
// --replay and the tests decode real device bytes rather than synthesised ones.
// It is the one fixture here whose response bytes were copied from a device
// rather than produced by our own encoder, which is what makes it worth
// keeping: it can catch a framing mistake that a generated fixture would share.
//
// Two honest caveats.
//
// Run 1 read once per command, so which command each transfer answers is an
// interpretation. The unsolicited 0x32 arrived first, before any reply, and Run
// 1 attributed it to nop. nop is no longer a step, so it leads the
// firmware_version exchange here — which is also the order it appeared on the
// wire. Runs 2, 3 and 4 saw no 0x32 on attach at all, so it is not a reply to
// anything.
//
// Run 1 sent 0xa8 with an EMPTY payload. The probe now sends the vendor's
// `00 00`, so the request below is not the one Run 1 made. Only the request
// changed: the responses are Run 1's bytes, and the vendor log records the same
// reply for `a8 00 00`.
func run1Script() []transport.Exchange {
	return []transport.Exchange{
		{Cmd: 0xa8, Payload: []byte{0x00, 0x00}, Responses: [][]byte{
			// Unsolicited 0x32, emitted on attach, before any reply.
			{0xa0, 0x14, 0x00, 0xb4, 0x32, 0x11, 0x00, 0x02, 0x00, 0x2f, 0x00, 0x1e, 0x01,
				0x38, 0x01, 0xff, 0x00, 0xf7, 0x00, 0x3f, 0x01, 0x34, 0x01, 0x73},
			// ACK for firmware_version, status 01.
			{0xa0, 0x06, 0x00, 0xa6, 0xb0, 0x03, 0x00, 0xa8, 0x01, 0x4e},
			// "GF_ITE_EC_20063".
			{0xa0, 0x14, 0x00, 0xb4, 0xa8, 0x11, 0x00, 0x47, 0x46, 0x5f, 0x49, 0x54, 0x45,
				0x5f, 0x45, 0x43, 0x5f, 0x32, 0x30, 0x30, 0x36, 0x33, 0x00, 0xe2},
		}},
	}
}

func explainOpenError(logger *log.Logger, err error) {
	switch {
	case errors.Is(err, transport.ErrPermission):
		logger.Printf("hint: there is no udev rule for this device yet — run under sudo")
	case errors.Is(err, transport.ErrNotFound):
		logger.Printf("hint: sensor not enumerated. Check `lsusb -d 27c6:5120`")
	}
}

func hexdump(b []byte) string {
	const max = 64
	var sb strings.Builder
	for i, c := range b {
		if i == max {
			fmt.Fprintf(&sb, "... (%d more)", len(b)-max)
			break
		}
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", c)
	}
	if sb.Len() == 0 {
		return "<empty>"
	}
	return sb.String()
}

// printable renders a payload as text when it plausibly is text — firmware
// version replies are ASCII strings, and spotting one immediately is the whole
// point of the probe.
func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7e {
			return ""
		}
		sb.WriteByte(c)
	}
	if sb.Len() < 3 {
		return ""
	}
	return sb.String()
}
