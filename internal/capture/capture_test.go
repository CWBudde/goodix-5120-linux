package capture

import (
	"bytes"
	"encoding/binary"
	"flag"
	"os"
	"testing"
	"time"

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

func interfaceDesc(linkType uint16) []byte { return interfaceDescResol(linkType, 0, false) }

// interfaceDescResol optionally carries an if_tsresol option, which USBPcap
// omits but other writers do not.
func interfaceDescResol(linkType uint16, resol byte, withOption bool) []byte {
	body := make([]byte, 0, 8)
	body = binary.LittleEndian.AppendUint16(body, linkType)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0x10000)
	if withOption {
		body = binary.LittleEndian.AppendUint16(body, optionTSResol)
		body = binary.LittleEndian.AppendUint16(body, 1)
		body = append(body, resol, 0, 0, 0) // one byte, padded to four
		body = binary.LittleEndian.AppendUint16(body, 0)
		body = binary.LittleEndian.AppendUint16(body, 0) // opt_endofopt
	}
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

func packetBlock(pkt []byte) []byte { return packetBlockAt(0, pkt) }

// packetBlockAt stamps the packet, in the interface's resolution units.
func packetBlockAt(ticks uint64, pkt []byte) []byte {
	body := make([]byte, 0, 20+len(pkt))
	body = binary.LittleEndian.AppendUint32(body, 0) // interface id
	body = binary.LittleEndian.AppendUint32(body, uint32(ticks>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(ticks))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(pkt)))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(pkt)))
	body = append(body, pkt...)
	return block(blockEnhancedPacket, body)
}

// deviceDescriptor is a minimal 27c6:5120 device descriptor reply.
func deviceDescriptor() []byte { return descriptorFor(0x27c6, 0x5120) }

func descriptorFor(vendor, product uint16) []byte {
	d := make([]byte, 18)
	d[0], d[1] = 0x12, 0x01
	binary.LittleEndian.PutUint16(d[8:10], vendor)
	binary.LittleEndian.PutUint16(d[10:12], product)
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
	addrs := FindDevices(ts, 0x27c6, 0x5120)
	if len(addrs) == 0 {
		t.Skip("capture holds no 27c6:5120 device descriptor")
	}
	t.Logf("the device appears at %d address(es): %v", len(addrs), addrs)

	s := Summarise(Frames(ts, addrs...), len(ts))
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

// --- re-enumeration: the same device under two numbers in one capture ---

// usec is a capture-start timestamp in microseconds since the epoch, which is
// the resolution USBPcap writes.
const usec = uint64(1_600_000_000_000_000)

// reenumeratedCapture is the shape a Device Manager Disable and Enable leaves
// behind: the sensor quiesces at one device number, disappears, and comes back
// at another. A second, unrelated device transfers throughout, the way the
// headset and mouse on the same hub did in disable-enable3.pcapng.
func reenumeratedCapture(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.Write(sectionHeader())
	buf.Write(interfaceDesc(LinkTypeUSBPcap))

	at := func(sec float64) uint64 { return usec + uint64(sec*1e6) }

	// Before: the sensor at device 2, quiescing with enable_chip(0).
	buf.Write(packetBlockAt(at(0), usbpcapPacket(2, 2, 0x80, transferControl, true, deviceDescriptor())))
	buf.Write(packetBlockAt(at(1), usbpcapPacket(2, 2, 0x01, transferBulk, false, proto.Encode(0x96, []byte{0x00, 0x02}))))

	// An unrelated device keeps transferring across the gap.
	buf.Write(packetBlockAt(at(2), usbpcapPacket(2, 7, 0x01, transferBulk, false, []byte{0xff})))
	buf.Write(packetBlockAt(at(20), usbpcapPacket(2, 7, 0x01, transferBulk, false, []byte{0xff})))

	// After: the same sensor, new device number, running an init.
	buf.Write(packetBlockAt(at(10), usbpcapPacket(2, 9, 0x80, transferControl, true, deviceDescriptor())))
	buf.Write(packetBlockAt(at(11), usbpcapPacket(2, 9, 0x01, transferBulk, false, proto.Encode(0x96, []byte{0x01, 0x02}))))
	buf.Write(packetBlockAt(at(12), usbpcapPacket(2, 9, 0x83, transferBulk, true, proto.Encode(proto.AckCmd, []byte{0x96, 0x01}))))

	return buf.Bytes()
}

// TestFindDevicesFollowsAReenumeration is the regression this whole change
// exists for. Reading only the first address reports the Disable and calls the
// Enable silent, which is the wrong conclusion drawn three times by hand.
func TestFindDevicesFollowsAReenumeration(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(reenumeratedCapture(t)))
	if err != nil {
		t.Fatal(err)
	}

	addrs := FindDevices(ts, 0x27c6, 0x5120)
	want := []Addr{{Bus: 2, Device: 2}, {Bus: 2, Device: 9}}
	if len(addrs) != len(want) {
		t.Fatalf("FindDevices = %v, want %v", addrs, want)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Errorf("address %d = %v, want %v", i, addrs[i], want[i])
		}
	}

	// The trap, pinned: one address sees only the traffic before the device came
	// back, and nothing in that result says the rest of the capture exists.
	if got := Frames(ts, addrs[0]); len(got) != 1 {
		t.Fatalf("one address gave %d frames, want 1", len(got))
	}

	frames := Frames(ts, addrs...)
	if len(frames) != 3 {
		t.Fatalf("got %d frames across both addresses, want 3", len(frames))
	}
	if frames[0].Addr.Device != 2 || !bytes.Equal(frames[0].Payload, []byte{0x00, 0x02}) {
		t.Errorf("frame 0 = %+v, want the quiesce at device 2", frames[0])
	}
	if frames[1].Addr.Device != 9 || !bytes.Equal(frames[1].Payload, []byte{0x01, 0x02}) {
		t.Errorf("frame 1 = %+v, want the init at device 9", frames[1])
	}
	if !frames[2].Ack || frames[2].Cmd != 0x96 {
		t.Errorf("frame 2 = %+v, want an ACK for 0x96", frames[2])
	}
	if d := frames[1].Time.Sub(frames[0].Time); d != 10*time.Second {
		t.Errorf("the two frames are %v apart, want 10s", d)
	}
}

// TestFramesWithNoAddressDecodesNothing: a variadic parameter makes an empty
// call legal, so say what it means rather than leaving it to be discovered.
func TestFramesWithNoAddressDecodesNothing(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(reenumeratedCapture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if got := Frames(ts); len(got) != 0 {
		t.Errorf("Frames with no address gave %d frames, want 0", len(got))
	}
}

func TestDevicesListsEveryAddress(t *testing.T) {
	ts, err := Transfers(bytes.NewReader(reenumeratedCapture(t)))
	if err != nil {
		t.Fatal(err)
	}

	devs := Devices(ts)
	if len(devs) != 3 {
		t.Fatalf("got %d device addresses, want 3", len(devs))
	}

	byAddr := map[Addr]Device{}
	for _, d := range devs {
		byAddr[d.Addr] = d
	}

	sensor := byAddr[Addr{Bus: 2, Device: 9}]
	if !sensor.ID || sensor.Vendor != 0x27c6 || sensor.Product != 0x5120 {
		t.Errorf("device 9 = %+v, want it identified as 27c6:5120", sensor)
	}
	if sensor.Bulk != 2 {
		t.Errorf("device 9 had %d bulk transfers, want 2", sensor.Bulk)
	}

	// The unrelated device has no descriptor here, and its span is what proves a
	// capture stayed alive while the sensor was silent.
	other := byAddr[Addr{Bus: 2, Device: 7}]
	if other.ID {
		t.Errorf("device 7 = %+v, want it reported as unidentified", other)
	}
	if got := other.Last.Sub(other.First); got != 18*time.Second {
		t.Errorf("device 7 spans %v, want 18s", got)
	}
}

func TestInterfaceTimeResolution(t *testing.T) {
	const ticks = 1_600_000_000_123_456

	// The specified default, and what USBPcap writes: microseconds.
	got, err := Interface{TSResol: 6}.Time(ticks)
	if err != nil {
		t.Fatal(err)
	}
	if got.UnixMicro() != ticks {
		t.Errorf("microsecond timestamp round-tripped to %d, want %d", got.UnixMicro(), ticks)
	}

	// Nanoseconds, where the naive microsecond assumption would be 1000x out.
	got, err = Interface{TSResol: 9}.Time(ticks)
	if err != nil {
		t.Fatal(err)
	}
	if got.UnixNano() != ticks {
		t.Errorf("nanosecond timestamp round-tripped to %d, want %d", got.UnixNano(), ticks)
	}

	// Binary resolution: 2^-10 s per tick.
	got, err = Interface{TSResol: 0x80 | 10}.Time(ticks)
	if err != nil {
		t.Fatal(err)
	}
	if got.Unix() != ticks>>10 {
		t.Errorf("binary timestamp gave %d seconds, want %d", got.Unix(), ticks>>10)
	}

	if _, err := (Interface{TSResol: 30}).Time(ticks); err == nil {
		t.Error("an impossible decimal resolution was accepted")
	}
}

// TestTSResolOptionIsRead covers the option parser end to end: a capture that
// declares nanoseconds must not be read as microseconds.
func TestTSResolOptionIsRead(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(sectionHeader())
	buf.Write(interfaceDescResol(LinkTypeUSBPcap, 9, true))
	buf.Write(packetBlockAt(2_000_000_000, usbpcapPacket(2, 2, 0x01, transferBulk, false, []byte{0x00})))

	ts, err := Transfers(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 {
		t.Fatalf("got %d transfers, want 1", len(ts))
	}
	if got := ts[0].Time.UTC(); got.Unix() != 2 {
		t.Errorf("timestamp = %v (unix %d), want 2 s past the epoch", got, got.Unix())
	}
}
