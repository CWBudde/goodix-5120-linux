// Command goodix-probe talks to the Goodix 27c6:5120 fingerprint sensor behind
// the ITE EC in a Huawei MateBook HVY-WXX9, one logged step at a time.
//
// It began as a read-only probe and is now the reference implementation of the
// whole path: the vendor init, the TLS-PSK handshake, image capture and finger
// detection, each confirmed on hardware (docs/protocol.md, Runs 11-21). The C
// libfprint driver (libfprint/goodix5120) follows its command sequence and is
// what runs day to day; this probe stays as the offline reference.
//
// Every live run goes through --bisect, which refuses
// to start the steps if the EC does not answer the initial 0xa8 health check.
// --dry-run and --bisect --replay run offline. Every frame
// passes the transport's safety gate; firmware-write opcodes are not compiled
// into this binary at all.
package main

import (
	"context"
	"encoding/binary"
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
	"goodix5120/internal/session"
	"goodix5120/internal/tlspsk"
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
		dryRun  = flag.Bool("dry-run", false, "print the frames a run can send, then exit; opens no USB device")
		timeout = flag.Duration("timeout", 5*time.Second, "per-transfer timeout")

		bisect    = flag.Bool("bisect", false, "attach, then one command per step, logging every reply. The only mode that sends anything (docs/protocol.md)")
		replay    = flag.Bool("replay", false, "--bisect: run against the replay fake (or, with --tls, a local openssl stand-in) instead of the device")
		stepList  = flag.String("steps", defaultBisectSteps(), "--bisect: comma-separated hex opcodes to send after attach, in order")
		logPath   = flag.String("log", "", "--bisect: log file, flushed after every line (default goodix-bisect-<time>.log)")
		readState = flag.Bool("read-state", false, "--bisect, live: if the EC ignores the 0xa8 health check, send ONE get_mcu_state (0xae) to learn which state it is in, then stop")

		useTLS        = flag.Bool("tls", false, "--bisect: after the steps, send 0xd0 and bridge the TLS-PSK handshake to a local openssl endpoint. Needs --allow-d0; live runs also need --psk")
		pskPath       = flag.String("psk", "", "--tls: file holding the raw 32-byte device PSK, as written by `goodix-dpapi -out` (a path, so the key stays out of shell history)")
		capture       = flag.String("capture", "", "--tls: ask for a frame (0x20) and write it here as a PGM. Needs --allow-20. BIOMETRIC data: keep it in gitignored captures/")
		waitFinger    = flag.Bool("wait-finger", false, "--capture: take the frame when the EC reports a touch, then wait for the lift. Needs --allow-32 and --allow-34")
		touches       = flag.Int("touches", 1, "--wait-finger: how many touch → frame → lift rounds to run in one TLS session. With more than one, frame N is written to FILE-N.pgm")
		fingerTimeout = flag.Duration("finger-timeout", 30*time.Second, "--wait-finger: how long to wait for each touch and each lift")
		wrongPSK      = flag.Bool("rehearse-rejection", false, "--tls --replay: give the stand-in a different key, to rehearse what a rejected PSK looks like")
	)

	// One --allow-<opcode> flag per above-ceiling opcode, registered from the
	// catalogue in bisect.go so an entry cannot be added without its flag.
	allowFlags := make(map[proto.Opcode]*bool, len(unlockable))
	for _, u := range unlockable {
		allowFlags[u.op] = flag.Bool(u.flag, false, u.help)
	}

	flag.Parse()

	logger := log.New(os.Stdout, "", 0)

	if *dryRun {
		dryRunFrames(logger)
		return
	}
	if !*bisect {
		logger.Print("nothing to do: live and replayed runs go through --bisect (docs/protocol.md).\n" +
			"Offline: --dry-run, or --bisect --replay")
		os.Exit(2)
	}
	if *readState && *replay {
		logger.Print("--read-state only works with a live --bisect: it asks a real EC why it ignored the health " +
			"check, and a rehearsal has no EC and runs no health check (TestReadStateOnAStuckEC covers it offline)")
		os.Exit(1)
	}
	if *wrongPSK && !(*useTLS && *replay) {
		logger.Print("--rehearse-rejection only works with --tls --replay: it is a rehearsal of the failure, " +
			"and deliberately sending a live EC a key it will reject teaches nothing")
		os.Exit(1)
	}

	allowed := make(map[proto.Opcode]bool, len(allowFlags))
	var allow []proto.Opcode
	for op, set := range allowFlags {
		if *set {
			allowed[op] = true
			allow = append(allow, op)
		}
	}
	tls := tlsConfig{
		enabled:  *useTLS,
		pskPath:  *pskPath,
		capture:  *capture,
		sendD4:   allowed[opTLSEstablished],
		getImage: allowed[opGetImage],

		waitFinger:    *waitFinger,
		touches:       *touches,
		fingerTimeout: *fingerTimeout,
		armDown:       allowed[opFDTDown],
		armUp:         allowed[opFDTUp],
	}
	os.Exit(mainBisect(*replay, *wrongPSK, *readState, allow, allowed, tls, *stepList, *logPath, *timeout))
}

// mainBisect runs bisect mode and returns the exit status: 0 if every step
// completed, 1 on any failure.
func mainBisect(replay, replayWrongPSK, readState bool, allow []proto.Opcode, allowed map[proto.Opcode]bool,
	tls tlsConfig, stepList, logPath string, timeout time.Duration) int {

	return mainBisectWithDeps(replay, replayWrongPSK, readState, allow, allowed,
		tls, stepList, logPath, timeout, bisectDependencies{
			newHost: func() bisectHost { return newLinuxHost(true) },
			openUSB: transport.OpenUSB, startTLS: tlspsk.Start,
		})
}

// The dependency boundary lets offline tests prove that local TLS failures
// stop before the host watcher or USB opener is reached.
type bisectDependencies struct {
	newHost  func() bisectHost
	openUSB  func(transport.Options) (transport.Transport, error)
	startTLS func(context.Context, tlspsk.Config) (*tlspsk.Session, error)
}

func mainBisectWithDeps(replay, replayWrongPSK, readState bool, allow []proto.Opcode, allowed map[proto.Opcode]bool,
	tls tlsConfig, stepList, logPath string, timeout time.Duration, deps bisectDependencies) int {

	stderr := log.New(os.Stderr, "", 0)
	ops, err := parseSteps(stepList, allow...)
	if err != nil {
		stderr.Printf("--steps: %v", err)
		return 1
	}
	// Check the flag combination before anything is opened: a --tls run that
	// cannot work should cost a message, not a live run.
	if err := tls.validate(ops, allowed, replay); err != nil {
		stderr.Printf("%v", err)
		return 1
	}
	tls.steps = ops
	prepared, err := prepareTLS(context.Background(), tls, replay, deps.startTLS)
	if err != nil {
		stderr.Printf("TLS preflight: %v", err)
		return 1
	}
	if prepared != nil {
		defer prepared.close()
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
	giveToSudoUser(stderr, f)

	var host bisectHost = offlineHost{}
	if !replay {
		host = deps.newHost()
	}

	opts := transport.Options{
		Ceiling: proto.ClassSafe, // never raised by this binary
		Timeout: timeout,
		Verbose: true, // the raw bytes are the point of a bisect run
		Logger:  logger,
	}
	// Admit above-ceiling opcodes to the transport, but only the ones this run
	// can actually send: the steps, plus the commands the TLS bridge sends at
	// points of its own. A flag set without either unlocks nothing. The ceiling
	// itself stays ClassSafe.
	var above []proto.Opcode
	for _, op := range slices.Concat(ops, tls.opcodes()) {
		if class, ok := op.Class(); ok && class != proto.ClassSafe && !slices.Contains(above, op) {
			above = append(above, op)
		}
	}
	allowedDesc := "none"
	if len(above) > 0 {
		opts.Allow = above
		names := make([]string, len(above))
		for i, op := range above {
			if st, ok := stepFor(op); ok {
				names[i] = fmt.Sprintf("%s (0x%02x)", st.purpose, byte(op))
			} else {
				names[i] = fmt.Sprintf("0x%02x", byte(op))
			}
		}
		allowedDesc = strings.Join(names, ", ")
	}
	// The raw TLS data path stays shut unless this is a --tls run.
	opts.AllowTLSData = tls.enabled

	// closeRehearsal tears down the `--tls --replay` stand-in, once open has
	// brought one up.
	var rehearsal *session.LoopbackEC
	open := func() (transport.Transport, error) {
		switch {
		case replay && tls.enabled:
			tr, ec, err := startRehearsal(context.Background(), logger, prepared, opts, replayWrongPSK)
			if err != nil {
				return nil, err
			}
			rehearsal = ec
			return tr, nil
		case replay:
			return transport.NewReplay(scriptFor(ops), opts), nil
		}
		return deps.openUSB(opts)
	}

	mode := "LIVE HARDWARE"
	if replay {
		mode = "replay (no USB)"
	}
	logger.Printf("goodix-probe bisect — %s, ceiling=%s, allowed above it: %s, steps=%s, log=%s",
		mode, proto.ClassSafe, allowedDesc, stepList, logPath)
	if tls.enabled {
		logger.Printf("  --tls: after the steps, request a TLS session and bridge the handshake (PLAN.md Phase 5b)")
	}

	var after func(transport.Transport) error
	if tls.enabled {
		after = func(tr transport.Transport) error {
			// rehearsal is nil for a live run and is set by open() otherwise.
			return runTLS(context.Background(), logger, tr, tls, rehearsal, prepared.host)
		}
	}

	// The health check is a live-hardware precondition: it asks the EC whether it
	// is in the state a run assumes. A rehearsal has no EC, and the scripted
	// replay answers a fixed list of exchanges, so an extra frame there would
	// desynchronise the script rather than check anything.
	health := healthCheck
	switch {
	case replay:
		health = healthOff
	case readState:
		health = healthReadState
	}
	err = runBisect(logger, host, open, ops, timeout, health, after)
	if rehearsal != nil {
		if cerr := rehearsal.Close(); cerr != nil {
			logger.Printf("tearing down the rehearsal stand-in: %v", cerr)
		}
	}
	switch {
	case err == nil:
		return 0
	default:
		logger.Printf("\nbisect failed: %v", err)
		if errors.Is(err, transport.ErrPermission) || errors.Is(err, transport.ErrNotFound) {
			explainOpenError(logger, err)
		}
		return 1
	}
}

// collect reads the responses to one command. The device answers with an ACK
// and then a separate data message, so it keeps reading until the data message
// arrives, the device goes quiet, or maxReadsPerStep is reached. Run 1 read
// once per command and so ran one transfer behind.
func collect(logger *log.Logger, tr transport.Transport, sent proto.Opcode, timeout time.Duration) error {
	return collectFrom(logger, tr, sent, timeout, false)
}

// collectFrom is collect for a caller that may already have read the ACK
// itself, so the data message that follows is not reported as unacknowledged.
func collectFrom(logger *log.Logger, tr transport.Transport, sent proto.Opcode, timeout time.Duration, acked bool) error {
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

		logger.Printf("  raw  %s", rawdump(raw))
		switch describe(logger, sent, raw) {
		case replyAck:
			acked = true
		case replyData, replyTLS:
			// get_mcu_state (0xae) and request_tls_connection (0xd0) answer
			// without acknowledging first, so a missing ACK here is normal
			// rather than a fault. Say which it was.
			if !acked {
				logger.Printf("  data arrived with no ACK — normal for 0xae and 0xd0")
			}
			return nil
		}
	}
	logger.Printf("  stopped after %d reads; the drain will collect anything left", maxReadsPerStep)
	return nil
}

// drain reads until the device goes quiet, so the probe never exits with a
// response left queued in the EC. Run 1 did exit that way; whether it
// contributed to the wedge is unknown (docs/protocol.md, Run 1), so this is hygiene, not a
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
		logger.Printf("  leftover raw  %s", rawdump(raw))
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
	replyTLS                // a TLS record, opaque without the PSK
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

	// A 0xb0 or 0xb2 pack carries a raw TLS record, not a message. Handing one
	// to DecodeMessage would report "inner message did not decode", which is
	// true but misleading: the frame is fine, it is simply encrypted. After
	// 0xd0 the EC opens a handshake, and every image arrives this way.
	if flags == proto.FlagTLSData || flags == proto.FlagTLSAlt {
		logger.Printf("  TLS record, %d bytes%s — opaque without the PSK", len(packPayload), tlsRecordSummary(packPayload))
		return replyTLS
	}

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
	if why, secret := proto.SecretReply(cmd); secret && len(msgPayload) > 0 {
		logger.Printf("  payload of %d byte(s) withheld: %s", len(msgPayload), why)
	} else if len(msgPayload) > 0 {
		logger.Printf("  payload %s", hexdump(msgPayload))
		if s := printable(msgPayload); s != "" {
			logger.Printf("  as text %q", s)
		}
	}
	return kind
}

// tlsRecordSummary names a TLS record's type and length from its five-byte
// header. Only the header is reported: the body is ciphertext of a fingerprint
// image, and nothing here may print it.
func tlsRecordSummary(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	kind := "type " + fmt.Sprintf("0x%02x", b[0])
	switch b[0] {
	case 0x14:
		kind = "change cipher spec"
	case 0x15:
		kind = "alert"
	case 0x16:
		kind = "handshake"
	case 0x17:
		kind = "application data"
	}
	return fmt.Sprintf(" (%s, TLS 1.%d, %d-byte record)", kind, int(b[2])-1, binary.BigEndian.Uint16(b[3:5]))
}

func dryRunFrames(logger *log.Logger) {
	logger.Printf("dry run — no USB device is opened, nothing is transmitted\n")

	logger.Printf("\n=== the default --steps ===")
	for _, st := range steps {
		printFrame(logger, "", st)
	}
	logger.Printf("\n%d frame(s). --steps may also name frames from the vendor sequence below; state-changing ones need their --allow-XX flag.", len(steps))

	// The vendor sequence is reference material, not a plan. Printing it is how
	// the PLAN.md Phase 4 gate — "each planned command matches the vendor
	// sequence byte for byte" — actually gets checked by a human.
	logger.Printf("\n\n=== the Windows driver's init sequence, for reference ===")
	logger.Printf("transcribed from the vendor ETW log (docs/protocol.md). --steps may name these, each behind its --allow-XX flag.")
	for i, st := range vendorInit {
		printFrame(logger, fmt.Sprintf("#%d ", i+1), st)
	}

	logger.Printf("\n\n=== the vendor's capture loop ===")
	logger.Printf("observed in dump.pcapng. Only --tls --capture sends 0x20 (behind --allow-20), and only --wait-finger")
	logger.Printf("sends the arms (behind --allow-32/--allow-34), with thresholds derived at run time rather than these.")
	for _, st := range vendorLoop {
		printFrame(logger, "", st)
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

// rawdump is hexdump for a transfer read from the device: a reply that
// proto.SecretPack names (the PSK hash in 0xe4's, the OTP in 0xa6's) is reduced
// to its pack header and command byte. Every "raw" line goes through it.
func rawdump(b []byte) string {
	op, why, secret := proto.SecretPack(b)
	if !secret {
		return hexdump(b)
	}
	return fmt.Sprintf("%s ... (0x%02x reply, %d more withheld: %s)", hexdump(b[:5]), byte(op), len(b)-5, why)
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
