package capture

import (
	"bytes"
	"encoding/binary"
	"flag"
	"os"
	"testing"

	"goodix5120/internal/proto"
)

// realCapture points the optional end-to-end test at a vendor capture. The
// captures are gitignored and biometric, so they are never required: without
// this flag the suite still covers the whole pipeline, over bytes built here.
var realCapture = flag.String("capture", "", "path to a USBPcap capture for TestAgainstRealCapture")

// --- a pcapng builder, so the tests need no fixture file ---

func block(typ uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	total := uint32(len(body) + 12)

	out := make([]byte, 0, total)
	out = binary.LittleEndian.AppendUint32(out, typ)
	out = binary.LittleEndian.AppendUint32(out, total)
	out = append(out, body...)
	return binary.LittleEndian.AppendUint32(out, total)
}

func sectionHeader() []byte {
	body := make([]byte, 0, 16)
	body = binary.LittleEndian.AppendUint32(body, byteOrderMagic)
	body = binary.LittleEndian.AppendUint16(body, 1) // major
	body = binary.LittleEndian.AppendUint16(body, 0) // minor
	body = binary.LittleEndian.AppendUint64(body, ^uint64(0))
	return block(blockSectionHeader, body)
}

func interfaceDesc(linkType uint16) []byte {
	body := make([]byte, 0, 8)
	body = binary.LittleEndian.AppendUint16(body, linkType)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0x10000)
	return block(blockInterfaceDesc, body)
}

// usbpcapPacket wraps data in the USBPcap pseudo-header.
func usbpcapPacket(bus, device uint16, endpoint, transfer byte, in bool, data []byte) []byte {
	h := make([]byte, usbpcapMinHeader)
	binary.LittleEndian.PutUint16(h[0:2], usbpcapMinHeader)
	if in {
		h[16] = 0x01
	}
	binary.LittleEndian.PutUint16(h[17:19], bus)
	binary.LittleEndian.PutUint16(h[19:21], device)
	h[21] = endpoint
	h[22] = transfer
	binary.LittleEndian.PutUint32(h[23:27], uint32(len(data)))
	return append(h, data...)
}

func packetBlock(pkt []byte) []byte {
	body := make([]byte, 0, 20+len(pkt))
	body = binary.LittleEndian.AppendUint32(body, 0) // interface id
	body = binary.LittleEndian.AppendUint32(body, 0) // timestamp high
	body = binary.LittleEndian.AppendUint32(body, 0) // timestamp low
	body = binary.LittleEndian.AppendUint32(body, uint32(len(pkt)))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(pkt)))
	body = append(body, pkt...)
	return block(blockEnhancedPacket, body)
}

// deviceDescriptor is a minimal 27c6:5120 device descriptor reply.
func deviceDescriptor() []byte {
	d := make([]byte, 18)
	d[0], d[1] = 0x12, 0x01
	binary.LittleEndian.PutUint16(d[8:10], 0x27c6)
	binary.LittleEndian.PutUint16(d[10:12], 0x5120)
	return d
}

// syntheticCapture builds a capture holding a descriptor, one outbound command
// and its ACK, plus traffic from an unrelated device that must be ignored.
func syntheticCapture(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(sectionHeader())
	buf.Write(interfaceDesc(LinkTypeUSBPcap))
	buf.Write(packetBlock(usbpcapPacket(2, 2, 0x80, transferControl, true, deviceDescriptor())))

	// firmware_version with the vendor payload, padded to 64 bytes the way the
	// host does, with non-zero padding standing in for the vendor's stack leak.
	tx := proto.Encode(0xa8, []byte{0x00, 0x00})
	padded := make([]byte, 64)
	for i := range padded {
		padded[i] = 0xde
	}
	copy(padded, tx)
	buf.Write(packetBlock(usbpcapPacket(2, 2, 0x01, transferBulk, false, padded)))

	ack := proto.Encode(proto.AckCmd, []byte{0xa8, 0x01})
	buf.Write(packetBlock(usbpcapPacket(2, 2, 0x83, transferBulk, true, ack)))

	// A different device on the same bus. Nothing from it may appear.
	buf.Write(packetBlock(usbpcapPacket(2, 7, 0x01, transferBulk, false, proto.Encode(0xa2, []byte{0x01, 0x14}))))

	return buf.Bytes()
}

func TestTransfersDecodesSyntheticCapture(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(syntheticCapture(t)))
	if err != nil {
		t.Fatalf("Transfers: %v", err)
	}
	if len(ts) != 4 {
		t.Fatalf("got %d transfers, want 4", len(ts))
	}
	if !ts[0].In || ts[0].Transfer != transferControl {
		t.Errorf("transfer 0 = %+v, want an inbound control transfer", ts[0])
	}
	if ts[1].In {
		t.Error("transfer 1 should be outbound")
	}
}

func TestFindDeviceUsesTheDescriptor(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(syntheticCapture(t)))
	if err != nil {
		t.Fatal(err)
	}
	addr, ok := FindDevice(ts, 0x27c6, 0x5120)
	if !ok {
		t.Fatal("FindDevice did not find the device")
	}
	if addr.Bus != 2 || addr.Device != 2 {
		t.Errorf("addr = %+v, want bus 2 device 2", addr)
	}
	if _, ok := FindDevice(ts, 0x1234, 0x5678); ok {
		t.Error("FindDevice found a device that is not in the capture")
	}
}

// TestFramesDropsPaddingAndOtherDevices covers the two rules that keep foreign
// bytes out of a fixture: only the named device is decoded, and everything past
// the declared pack length is discarded. The vendor driver does not zero its
// 64-byte padding, so those trailing bytes are Windows kernel stack memory.
func TestFramesDropsPaddingAndOtherDevices(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(syntheticCapture(t)))
	if err != nil {
		t.Fatal(err)
	}

	frames := Frames(ts, Addr{Bus: 2, Device: 2})
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2 (the other device's traffic must be ignored)", len(frames))
	}

	tx := frames[0]
	if tx.Err != nil {
		t.Fatalf("outbound frame did not decode: %v", tx.Err)
	}
	if tx.Cmd != 0xa8 {
		t.Errorf("Cmd = 0x%02x, want 0xa8", byte(tx.Cmd))
	}
	if !bytes.Equal(tx.Payload, []byte{0x00, 0x00}) {
		t.Errorf("payload = %x, want 0000 — the 0xde padding must be gone", tx.Payload)
	}
	if bytes.Contains(tx.Pack, []byte{0xde, 0xde}) {
		t.Error("padding bytes survived into the pack payload")
	}

	ack := frames[1]
	if !ack.Ack || ack.Cmd != 0xa8 || ack.Status != 0x01 {
		t.Errorf("second frame = %+v, want an ACK for 0xa8 with status 1", ack)
	}
}

func TestSummariseCountsWithoutPayloads(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(syntheticCapture(t)))
	if err != nil {
		t.Fatal(err)
	}
	s := Summarise(Frames(ts, Addr{Bus: 2, Device: 2}), len(ts))

	if s.Failed != 0 {
		t.Errorf("%d frames failed to decode, want 0", s.Failed)
	}
	if s.TXCommands[0xa8] != 1 {
		t.Errorf("TX 0xa8 counted %d times, want 1", s.TXCommands[0xa8])
	}
	if s.Acks[0xa8] != 1 {
		t.Errorf("ACK for 0xa8 counted %d times, want 1", s.Acks[0xa8])
	}
	if got := s.PayloadLengths[0xa8][2]; got != 1 {
		t.Errorf("payload length 2 counted %d times, want 1", got)
	}
}

func TestRejectsNonUSBPcapLinkType(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(sectionHeader())
	buf.Write(interfaceDesc(1)) // Ethernet
	buf.Write(packetBlock([]byte{0, 1, 2, 3}))

	if _, err := Transfers(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("a non-USBPcap capture was accepted; a usbmon header would be misread as USBPcap")
	}
}

func TestRejectsTruncatedFile(t *testing.T) {
	full := syntheticCapture(t)
	if _, err := Transfers(bytes.NewReader(full[:len(full)-7])); err == nil {
		t.Fatal("a truncated capture was accepted")
	}
}

// TestAgainstRealCapture runs the pipeline over a vendor capture when one is
// supplied. It asserts only structural facts, never byte values, so it can be
// left in the repository without the capture.
func TestAgainstRealCapture(t *testing.T) {
	if *realCapture == "" {
		t.Skip("no -capture given; the vendor captures are gitignored")
	}

	f, err := os.Open(*realCapture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ts, err := Transfers(f)
	if err != nil {
		t.Fatalf("Transfers: %v", err)
	}
	addr, ok := FindDevice(ts, 0x27c6, 0x5120)
	if !ok {
		t.Skip("capture holds no 27c6:5120 device descriptor")
	}

	s := Summarise(Frames(ts, addr), len(ts))
	if s.Frames == 0 {
		t.Fatal("no frames decoded for the device")
	}
	if s.Failed != 0 {
		t.Errorf("%d of %d frames failed to decode; every checksum in the vendor captures verifies",
			s.Failed, s.Frames)
	}
	for op, lens := range s.PayloadLengths {
		for n := range lens {
			if err := op.CheckPayload(n); err != nil {
				t.Errorf("the vendor sent 0x%02x with %d bytes, which our registered rule refuses: %v",
					byte(op), n, err)
			}
		}
	}
}
