// Command goodix-pcap reads a USBPcap capture of the 27c6:5120 offline.
//
// It opens no device and writes no file: input is a path, output is stdout.
// That is deliberate. This repository's whole safety argument rests on the
// probe being the only thing that can talk to the embedded controller, and a
// capture tool has no business being able to.
//
// The default mode prints counts only — no payload bytes at all — because a
// capture of this device contains a hash of the device PSK, its OTP, and TLS
// records holding fingerprint images. Use it first on any new capture.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"goodix5120/internal/capture"
	"goodix5120/internal/proto"
)

const (
	vendorID  = 0x27c6
	productID = 0x5120
)

func main() {
	var (
		in      = flag.String("in", "", "pcapng file to read (required)")
		frames  = flag.Bool("frames", false, "also list every frame: opcode, direction and payload LENGTH, still no payload bytes")
		bus     = flag.Int("bus", 0, "bus number, if the capture holds no device descriptor to find it with")
		dev     = flag.Int("device", 0, "device number, with -bus")
		show    = flag.String("show", "", "print the payload BYTES of one opcode, in hex (e.g. ae). Refused for opcodes whose replies carry secrets")
		devices = flag.Bool("devices", false, "list every device address in the capture and stop: which hub this is, and who kept transferring")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)
	if *in == "" {
		logger.Print("usage: goodix-pcap -in capture.pcapng [-devices] [-frames]")
		os.Exit(2)
	}

	if err := run(logger, *in, *frames, *devices, *show, uint16(*bus), uint16(*dev)); err != nil {
		logger.Printf("goodix-pcap: %v", err)
		os.Exit(1)
	}
}

// secret names the opcodes whose payloads must never be printed, whatever is
// asked for. The 0xe4 reply carries a hash of the device PSK, the 0xa6 reply is
// the OTP, and a TLS pack is ciphertext of a fingerprint image. This is a
// deny list rather than a judgement call at the call site, so adding a new way
// to print bytes cannot quietly reopen one of these.
var secret = map[proto.Opcode]string{
	0xe4: "the reply carries a hash of the device PSK",
	0xa6: "the reply is the device OTP",
}

func parseShow(spec string) (proto.Opcode, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(spec)), "0x"), 16, 8)
	if err != nil {
		return 0, fmt.Errorf("bad -show opcode %q: %w", spec, err)
	}
	op := proto.Opcode(v)
	if why, no := secret[op]; no {
		return 0, fmt.Errorf("refusing to print 0x%02x: %s", byte(op), why)
	}
	return op, nil
}

func run(logger *log.Logger, path string, listFrames, listDevices bool, show string, bus, device uint16) error {
	var showOp proto.Opcode
	showing := show != ""
	if showing {
		op, err := parseShow(show)
		if err != nil {
			return err
		}
		showOp = op
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	transfers, err := capture.Transfers(f)
	if err != nil {
		return err
	}

	if len(transfers) == 0 {
		return fmt.Errorf("the capture holds no USB transfers at all")
	}
	seen := capture.Devices(transfers)
	t0 := transfers[0].Time

	if listDevices {
		printDevices(logger, seen, t0, transfers)
		return nil
	}

	addrs := []capture.Addr{{Bus: bus, Device: device}}
	if bus == 0 && device == 0 {
		addrs = capture.FindDevices(transfers, vendorID, productID)
		if len(addrs) == 0 {
			return fmt.Errorf("no %04x:%04x device descriptor in the capture; run with -devices to see what is here, then pass -bus and -device", vendorID, productID)
		}
		if len(addrs) == 1 {
			logger.Printf("found %04x:%04x at %s, from its device descriptor", vendorID, productID, addrs[0])
		} else {
			// This is the case that used to be read as "the sensor went quiet":
			// the device came back under a new number and everything after the
			// re-enumeration was being dropped on the floor.
			logger.Printf("found %04x:%04x at %d addresses — it re-enumerated during the capture:",
				vendorID, productID, len(addrs))
			for _, a := range addrs {
				logger.Printf("  %s", withSpan(a, seen, t0))
			}
			logger.Printf("  all of them are decoded together below, in capture order")
		}
		if late := lateUnidentified(seen, addrs); len(late) > 0 {
			logger.Printf("note: %d address(es) carrying bulk traffic appear after this device's last transfer,"+
				" with no descriptor to identify them.", len(late))
			logger.Printf("      If the sensor came back under a new number, its init is in there: run -devices," +
				" then -bus/-device.")
		}
	}

	frames := capture.Frames(transfers, addrs...)
	s := capture.Summarise(frames, len(transfers))

	logger.Printf("\ncapture starts %s and runs %s", stamp(t0),
		since(transfers[len(transfers)-1].Time, t0))
	logger.Printf("%d USB transfers, %d on this device", s.Transfers, s.Frames)
	logger.Printf("%d frames decoded, %d failed to decode", s.Decoded, s.Failed)
	if s.Failed == 0 && s.Frames > 0 {
		logger.Printf("every pack and message checksum verifies")
	}

	logger.Printf("\nTX commands (payload lengths observed):")
	for _, op := range sortedOps(s.TXCommands) {
		logger.Printf("  %-32s 0x%02x  x%-4d  %s", name(op), byte(op), s.TXCommands[op], lengths(s.PayloadLengths[op]))
	}

	logger.Printf("\nRX messages:")
	for _, op := range sortedOps(s.RXMessages) {
		logger.Printf("  %-32s 0x%02x  x%d", name(op), byte(op), s.RXMessages[op])
	}

	logger.Printf("\nACKs, by acknowledged command:")
	for _, op := range sortedOps(s.Acks) {
		logger.Printf("  %-32s 0x%02x  x%d", name(op), byte(op), s.Acks[op])
	}

	if s.TLSPacks > 0 {
		logger.Printf("\n%d TLS packs (lengths): %s", s.TLSPacks, lengths(s.TLSLengths))
		logger.Printf("  their contents are ciphertext of fingerprint images and are never printed")
	}

	if showing {
		logger.Printf("\npayloads of %s (0x%02x):", name(showOp), byte(showOp))
		for i, fr := range frames {
			if fr.Err != nil || fr.TLS() || fr.Ack || fr.Cmd != showOp {
				continue
			}
			dir := "TX"
			if fr.In {
				dir = "RX"
			}
			logger.Printf("  %4d %9s %s %d bytes: %x", i, since(fr.Time, t0), dir, len(fr.Payload), fr.Payload)
		}
	}

	if listFrames {
		logger.Printf("\nframes, in capture order (lengths only):")
		multi := len(addrs) > 1
		for i, fr := range frames {
			at := ""
			if multi {
				at = fmt.Sprintf(" [dev %d]", fr.Addr.Device)
			}
			logger.Printf("  %4d %9s%s %s", i, since(fr.Time, t0), at, describe(fr))
		}
	}
	return nil
}

func describe(f capture.Frame) string {
	dir := "TX"
	if f.In {
		dir = "RX"
	}
	switch {
	case f.Err != nil:
		return fmt.Sprintf("%s UNDECODED: %v", dir, f.Err)
	case f.TLS():
		return fmt.Sprintf("%s TLS pack, %d bytes", dir, len(f.Pack))
	case f.Ack:
		return fmt.Sprintf("%s ACK for %s (0x%02x), status 0x%02x", dir, name(f.Cmd), byte(f.Cmd), f.Status)
	default:
		return fmt.Sprintf("%s %s (0x%02x), %d-byte payload", dir, name(f.Cmd), byte(f.Cmd), len(f.Payload))
	}
}

func name(op proto.Opcode) string {
	if n := op.Name(); n != "" {
		return n
	}
	return "<unregistered>"
}

func sortedOps(m map[proto.Opcode]int) []proto.Opcode {
	out := make([]proto.Opcode, 0, len(m))
	for op := range m {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func lengths(m map[int]int) string {
	if len(m) == 0 {
		return "none"
	}
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	s := ""
	for i, k := range keys {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%d bytes x%d", k, m[k])
	}
	return s
}

// stamp formats an absolute capture time in this machine's local zone, named
// explicitly. pcapng timestamps are UTC; printing them that way against a
// capture taken in CEST silently shifts every event by two hours.
func stamp(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05.000 MST") }

// since formats a capture-relative time. Every timestamp this tool prints is
// relative to the first transfer in the file, because what a capture is asked
// is almost always "how long after the start", not "at what wall-clock time".
func since(t, t0 time.Time) string {
	return fmt.Sprintf("%.3fs", t.Sub(t0).Seconds())
}

// printDevices answers the first question a new capture raises: is the sensor
// even on this hub, and did everything else keep transferring while it was
// silent? USBPcap renumbers its filter devices per boot and per hub topology,
// so "the same interface as last time" can be a different hub entirely.
func printDevices(logger *log.Logger, devs []capture.Device, t0 time.Time, transfers []capture.Transfer) {
	end := transfers[len(transfers)-1].Time
	logger.Printf("%d device addresses, %d USB transfers, over %s from %s",
		len(devs), len(transfers), since(end, t0), stamp(t0))
	logger.Printf("\n  address             id          transfers    bulk      first       last")
	for _, d := range devs {
		id := "(no descriptor)"
		if d.ID {
			id = fmt.Sprintf("%04x:%04x", d.Vendor, d.Product)
		}
		marker := ""
		if d.ID && d.Vendor == vendorID && d.Product == productID {
			marker = "  <- the sensor"
		}
		logger.Printf("  %-18s  %-15s %6d  %6d  %9s  %9s%s",
			d.Addr, id, d.Transfers, d.Bulk, since(d.First, t0), since(d.Last, t0), marker)
	}
	logger.Printf("\nAn address with no descriptor attached before the capture started and was not")
	logger.Printf("covered by USBPcap's descriptor sweep. Tick \"Inject already connected devices")
	logger.Printf("descriptors\" to identify them.")
}

// withSpan describes one address with the transfer span observed at it.
func withSpan(a capture.Addr, devs []capture.Device, t0 time.Time) string {
	for _, d := range devs {
		if d.Addr == a {
			return fmt.Sprintf("%-18s %d transfers (%d bulk), %s .. %s",
				a, d.Transfers, d.Bulk, since(d.First, t0), since(d.Last, t0))
		}
	}
	return a.String()
}

// lateUnidentified names addresses that carry bulk traffic, have no descriptor
// in the capture, and first appear only after the located device fell silent.
//
// That is the exact shape of a re-enumeration whose descriptor sweep was
// missed: the sensor comes back under a new number and nothing in the file
// says so. Reporting it is cheaper than reading "3 frames" for a third time
// and concluding the driver sent nothing.
func lateUnidentified(devs []capture.Device, found []capture.Addr) []capture.Addr {
	var last time.Time
	is := map[capture.Addr]bool{}
	for _, a := range found {
		is[a] = true
	}
	for _, d := range devs {
		if is[d.Addr] && d.Last.After(last) {
			last = d.Last
		}
	}

	var out []capture.Addr
	for _, d := range devs {
		if !is[d.Addr] && !d.ID && d.Bulk > 0 && d.First.After(last) {
			out = append(out, d.Addr)
		}
	}
	return out
}
