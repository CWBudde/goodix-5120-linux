package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// USB transfer types as USBPcap reports them.
const (
	transferIsochronous = 0
	transferInterrupt   = 1
	transferControl     = 2
	transferBulk        = 3
)

// usbpcapMinHeader is the fixed part of the USBPcap pseudo-header: headerLen,
// irpId, status, function, info, bus, device, endpoint, transfer, dataLength.
const usbpcapMinHeader = 2 + 8 + 4 + 2 + 1 + 2 + 2 + 1 + 1 + 4

// Transfer is one USB transfer with its payload.
type Transfer struct {
	Bus      uint16
	Device   uint16
	Endpoint byte // as reported, so the 0x80 IN bit is still set
	Transfer byte
	In       bool
	Time     time.Time
	Data     []byte
}

// Addr identifies a device on a captured bus.
//
// A USB device number is not stable: unplug and replug a device, or disable and
// re-enable it in Device Manager, and Windows gives it a new one within the
// same capture. Nothing here may assume one device has one address.
type Addr struct {
	Bus    uint16
	Device uint16
}

func (a Addr) String() string { return fmt.Sprintf("bus %d device %d", a.Bus, a.Device) }

// decodeUSBPcap decodes one USBPcap packet body.
//
// It trusts the header's own headerLen to find the payload rather than assuming
// a fixed size: control and isochronous packets carry extra fields, and a
// future USBPcap could add more.
func decodeUSBPcap(b []byte, order binary.ByteOrder, ts time.Time) (Transfer, error) {
	if len(b) < usbpcapMinHeader {
		return Transfer{}, fmt.Errorf("%w: USBPcap header is %d bytes", ErrFormat, len(b))
	}

	headerLen := int(order.Uint16(b[0:2]))
	if headerLen < usbpcapMinHeader || headerLen > len(b) {
		return Transfer{}, fmt.Errorf("%w: USBPcap headerLen %d in a %d-byte packet", ErrFormat, headerLen, len(b))
	}

	t := Transfer{
		Bus:      order.Uint16(b[17:19]),
		Device:   order.Uint16(b[19:21]),
		Endpoint: b[21],
		Transfer: b[22],
		Time:     ts,
	}
	// info bit 0 set means the packet travelled from the device to the host.
	t.In = b[16]&0x01 != 0 || t.Endpoint&0x80 != 0

	dataLen := int(order.Uint32(b[23:27]))
	payload := b[headerLen:]
	if dataLen < len(payload) {
		payload = payload[:dataLen]
	}
	t.Data = payload
	return t, nil
}

// Transfers decodes every USB transfer in a pcapng stream, in capture order.
//
// It requires the capture to declare LinkTypeUSBPcap: a Linux usbmon capture
// has a different pseudo-header, and silently misreading one as the other would
// produce plausible nonsense.
func Transfers(r io.Reader) ([]Transfer, error) {
	rd := NewReader(r)
	var out []Transfer
	for {
		blk, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if blk.Type != blockEnhancedPacket {
			continue
		}
		// Enhanced packet block: interface id, timestamp high and low, captured
		// length, original length, then the packet data.
		const ephLen = 20
		if len(blk.Body) < ephLen {
			return nil, fmt.Errorf("%w: short enhanced packet block", ErrFormat)
		}
		id := int(blk.ByteOrder.Uint32(blk.Body[0:4]))
		if id >= len(rd.Interfaces()) {
			return nil, fmt.Errorf("%w: packet names interface %d, which was never described", ErrFormat, id)
		}
		iface := rd.Interfaces()[id]
		if iface.LinkType != LinkTypeUSBPcap {
			return nil, fmt.Errorf("%w: interface %d has link type %d, want %d (USBPcap)", ErrFormat, id, iface.LinkType, LinkTypeUSBPcap)
		}

		// The timestamp is one 64-bit count split across two 32-bit fields.
		ticks := uint64(blk.ByteOrder.Uint32(blk.Body[4:8]))<<32 | uint64(blk.ByteOrder.Uint32(blk.Body[8:12]))
		when, err := iface.Time(ticks)
		if err != nil {
			return nil, err
		}

		capLen := int(blk.ByteOrder.Uint32(blk.Body[12:16]))
		if ephLen+capLen > len(blk.Body) {
			return nil, fmt.Errorf("%w: captured length %d exceeds the block", ErrFormat, capLen)
		}
		t, err := decodeUSBPcap(blk.Body[ephLen:ephLen+capLen], blk.ByteOrder, when)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// descriptorID reads the vendor and product id out of a GET_DESCRIPTOR(DEVICE)
// reply. It reports false for any other transfer.
func descriptorID(t Transfer) (vendor, product uint16, ok bool) {
	// A device descriptor is 18 bytes: bLength=0x12, bDescriptorType=0x01,
	// with idVendor at offset 8 and idProduct at 10, both little endian.
	if t.Transfer != transferControl || len(t.Data) < 12 {
		return 0, 0, false
	}
	if t.Data[0] != 0x12 || t.Data[1] != 0x01 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint16(t.Data[8:10]), binary.LittleEndian.Uint16(t.Data[10:12]), true
}

// FindDevices locates every address at which a vendor and product id appears,
// using the GET_DESCRIPTOR(DEVICE) replies in the capture itself. That is more
// honest than hardcoding a bus address, which changes between captures.
//
// It returns more than one address when the device re-enumerated during the
// capture — a Device Manager Disable and Enable, or an Uninstall and rescan,
// brings it back with a new device number. Taking only the first address there
// would silently analyse the half of the capture before the re-enumeration and
// report the other half as absent.
//
// Addresses come back in the order their descriptors were captured.
func FindDevices(ts []Transfer, vendor, product uint16) []Addr {
	var out []Addr
	seen := map[Addr]bool{}
	for _, t := range ts {
		v, p, ok := descriptorID(t)
		if !ok || v != vendor || p != product {
			continue
		}
		a := Addr{Bus: t.Bus, Device: t.Device}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// FindDevice returns the first address at which the device appears.
//
// Prefer FindDevices unless one address is genuinely all that is wanted: this
// cannot represent a device that re-enumerated mid-capture.
func FindDevice(ts []Transfer, vendor, product uint16) (Addr, bool) {
	addrs := FindDevices(ts, vendor, product)
	if len(addrs) == 0 {
		return Addr{}, false
	}
	return addrs[0], true
}

// Device is every address seen in a capture, with what can be said about it
// without reading a byte of its payloads.
type Device struct {
	Addr Addr
	// Vendor and Product come from a device descriptor in the capture. ID is
	// false when no descriptor for this address was captured, which is the
	// normal case for a device that attached before the capture started and was
	// not covered by USBPcap's descriptor sweep.
	Vendor, Product uint16
	ID              bool
	Transfers       int
	Bulk            int
	First, Last     time.Time
}

// Devices lists every device address in a capture, in first-seen order.
//
// This answers the first question any new capture raises — is the sensor even
// on this hub, and did it keep transferring — without decoding a single
// payload. USBPcap's filter-device numbers are renumbered per boot and per hub
// topology, so a capture taken from the "same" interface as the last one may
// hold entirely different devices.
func Devices(ts []Transfer) []Device {
	var out []Device
	at := map[Addr]int{}
	for _, t := range ts {
		a := Addr{Bus: t.Bus, Device: t.Device}
		i, ok := at[a]
		if !ok {
			i = len(out)
			at[a] = i
			out = append(out, Device{Addr: a, First: t.Time})
		}
		d := &out[i]
		d.Transfers++
		if t.Transfer == transferBulk {
			d.Bulk++
		}
		if t.Time.Before(d.First) {
			d.First = t.Time
		}
		if t.Time.After(d.Last) {
			d.Last = t.Time
		}
		if v, p, ok := descriptorID(t); ok && !d.ID {
			d.Vendor, d.Product, d.ID = v, p, true
		}
	}
	return out
}
