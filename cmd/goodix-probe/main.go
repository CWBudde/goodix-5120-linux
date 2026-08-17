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
	"log"
	"os"
	"strings"
	"time"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// The read-only interrogation sequence. Order matters: nop is the cheapest
// liveness check, so a device that fails there tells us to stop before trying
// anything more elaborate.
var steps = []struct {
	cmd     proto.Opcode
	purpose string
}{
	{0x00, "liveness check — expect an ACK with bit 0 set"},
	{0xa8, "firmware version — THE go/no-go signal"},
	{0xa6, "OTP calibration data"},
	{0xe4, "stored PSK metadata (read, never write)"},
}

func main() {
	var (
		dryRun  = flag.Bool("dry-run", false, "decode and print the frames that would be sent, then exit without opening any USB device")
		replay  = flag.Bool("replay", false, "run against the built-in replay fake instead of real hardware")
		verbose = flag.Bool("v", false, "log every transfer as hex")
		timeout = flag.Duration("timeout", 5*time.Second, "per-transfer timeout")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)

	if *dryRun {
		dryRunFrames(logger)
		return
	}

	opts := transport.Options{
		Ceiling: proto.ClassSafe, // never raised by this binary
		Timeout: *timeout,
		Verbose: *verbose,
		Logger:  logger,
	}

	var tr transport.Transport
	if *replay {
		tr = transport.NewReplay(replayScript(), opts)
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

func run(logger *log.Logger, tr transport.Transport, timeout time.Duration) error {
	logger.Printf("probing Goodix 27c6:5120 — read-only, ceiling=%s\n", proto.ClassSafe)

	for _, step := range steps {
		name := step.cmd.Name()
		if name == "" {
			name = "<unregistered>"
		}
		logger.Printf("\n--- %s (0x%02x) — %s", name, byte(step.cmd), step.purpose)

		if err := tr.Send(step.cmd, nil); err != nil {
			return fmt.Errorf("send %s: %w", name, err)
		}

		raw, err := tr.Recv(timeout)
		if err != nil {
			// A timeout on the very first step is the signal that this device
			// does not speak the 51x0 protocol at all — report it as such
			// rather than as a generic I/O error.
			return fmt.Errorf("recv after %s: %w", name, err)
		}
		if len(raw) == 0 {
			logger.Printf("  no response (device stayed silent)")
			continue
		}

		logger.Printf("  raw  %s", hexdump(raw))
		describe(logger, step.cmd, raw)
	}

	logger.Printf("\ndone. Record anything notable in docs/protocol.md under \"Observed exchanges\".")
	return nil
}

// describe decodes a response as far as it can, reporting honestly at the point
// it stops making sense rather than inventing structure.
func describe(logger *log.Logger, sent proto.Opcode, raw []byte) {
	flags, packPayload, err := proto.DecodePack(raw)
	if err != nil {
		logger.Printf("  outer frame did not decode: %v", err)
		logger.Printf("  (this is itself informative — the 5120 may not use 51x0 framing)")
		return
	}
	logger.Printf("  pack flags=0x%02x payload=%d bytes", flags, len(packPayload))

	cmd, msgPayload, err := proto.DecodeMessage(packPayload)
	if err != nil {
		logger.Printf("  inner message did not decode: %v", err)
		return
	}

	switch {
	case proto.IsAck(sent, cmd):
		logger.Printf("  ACK for 0x%02x — 51x0 ACK convention holds", byte(sent))
	default:
		logger.Printf("  message cmd=0x%02x (%s)", byte(cmd), cmd.Name())
	}

	if len(msgPayload) > 0 {
		logger.Printf("  payload %s", hexdump(msgPayload))
		if s := printable(msgPayload); s != "" {
			logger.Printf("  as text %q", s)
		}
	}
}

func dryRunFrames(logger *log.Logger) {
	logger.Printf("dry run — no USB device is opened, nothing is transmitted\n")
	for _, step := range steps {
		frame := proto.Encode(step.cmd, nil)
		class, ok := step.cmd.Class()
		status := "UNREGISTERED — would be refused"
		if ok {
			status = class.String()
		}
		logger.Printf("\n%s (0x%02x) [%s]\n  %s\n  %s",
			step.cmd.Name(), byte(step.cmd), status, step.purpose, hexdump(frame))
	}
	logger.Printf("\n%d frames. Verify the framing by hand against docs/protocol.md before running live.", len(steps))
}

// replayScript exercises the full decode path with no hardware attached. The
// responses are synthesised, not captured — they prove the plumbing works, and
// deliberately prove nothing about the real device.
func replayScript() []transport.Exchange {
	out := make([]transport.Exchange, 0, len(steps))
	for _, step := range steps {
		ack := proto.Encode(proto.Opcode(byte(step.cmd)|0x01), nil)
		out = append(out, transport.Exchange{Cmd: step.cmd, Response: ack})
	}
	return out
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
