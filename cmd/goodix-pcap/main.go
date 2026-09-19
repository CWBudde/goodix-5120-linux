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

	"goodix5120/internal/capture"
	"goodix5120/internal/proto"
)

const (
	vendorID  = 0x27c6
	productID = 0x5120
)

func main() {
	var (
		in     = flag.String("in", "", "pcapng file to read (required)")
		frames = flag.Bool("frames", false, "also list every frame: opcode, direction and payload LENGTH, still no payload bytes")
		bus    = flag.Int("bus", 0, "bus number, if the capture holds no device descriptor to find it with")
		dev    = flag.Int("device", 0, "device number, with -bus")
		show   = flag.String("show", "", "print the payload BYTES of one opcode, in hex (e.g. ae). Refused for opcodes whose replies carry secrets")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)
	if *in == "" {
		logger.Print("usage: goodix-pcap -in capture.pcapng [-frames]")
		os.Exit(2)
	}

	if err := run(logger, *in, *frames, *show, uint16(*bus), uint16(*dev)); err != nil {
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

func run(logger *log.Logger, path string, listFrames bool, show string, bus, device uint16) error {
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

	addr := capture.Addr{Bus: bus, Device: device}
	if bus == 0 && device == 0 {
		found, ok := capture.FindDevice(transfers, vendorID, productID)
		if !ok {
			return fmt.Errorf("no %04x:%04x device descriptor in the capture; pass -bus and -device", vendorID, productID)
		}
		addr = found
		logger.Printf("found %04x:%04x at bus %d device %d, from its device descriptor",
			vendorID, productID, addr.Bus, addr.Device)
	}

	frames := capture.Frames(transfers, addr)
	s := capture.Summarise(frames, len(transfers))

	logger.Printf("\n%d USB transfers, %d on this device", s.Transfers, s.Frames)
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
			logger.Printf("  %4d %s %d bytes: %x", i, dir, len(fr.Payload), fr.Payload)
		}
	}

	if listFrames {
		logger.Printf("\nframes, in capture order (lengths only):")
		for i, fr := range frames {
			logger.Printf("  %4d %s", i, describe(fr))
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
