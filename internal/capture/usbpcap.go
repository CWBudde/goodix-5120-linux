package capture

import (
	"encoding/binary"
	"fmt"
	"io"
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
	Data     []byte
}

// Addr identifies a device on a captured bus.
type Addr struct {
	Bus    uint16
	Device uint16
}

// decodeUSBPcap decodes one USBPcap packet body.
//
// It trusts the header's own headerLen to find the payload rather than assuming
// a fixed size: control and isochronous packets carry extra fields, and a
// future USBPcap could add more.
func decodeUSBPcap(b []byte, order binary.ByteOrder) (Transfer, error) {
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
		iface := int(blk.ByteOrder.Uint32(blk.Body[0:4]))
		if iface >= len(rd.LinkTypes()) {
			return nil, fmt.Errorf("%w: packet names interface %d, which was never described", ErrFormat, iface)
		}
		if lt := rd.LinkTypes()[iface]; lt != LinkTypeUSBPcap {
			return nil, fmt.Errorf("%w: interface %d has link type %d, want %d (USBPcap)", ErrFormat, iface, lt, LinkTypeUSBPcap)
		}

		capLen := int(blk.ByteOrder.Uint32(blk.Body[12:16]))
		if ephLen+capLen > len(blk.Body) {
			return nil, fmt.Errorf("%w: captured length %d exceeds the block", ErrFormat, capLen)
		}
		t, err := decodeUSBPcap(blk.Body[ephLen:ephLen+capLen], blk.ByteOrder)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// FindDevice locates a device by vendor and product id, using the
// GET_DESCRIPTOR(DEVICE) reply in the capture itself. That is more honest than
// hardcoding a bus address, which changes between captures.
//
// It returns false if no descriptor for that id was captured.
func FindDevice(ts []Transfer, vendor, product uint16) (Addr, bool) {
	for _, t := range ts {
		// A device descriptor is 18 bytes: bLength=0x12, bDescriptorType=0x01,
		// with idVendor at offset 8 and idProduct at 10, both little endian.
		if t.Transfer != transferControl || len(t.Data) < 12 {
			continue
		}
		if t.Data[0] != 0x12 || t.Data[1] != 0x01 {
			continue
		}
		if binary.LittleEndian.Uint16(t.Data[8:10]) == vendor &&
			binary.LittleEndian.Uint16(t.Data[10:12]) == product {
			return Addr{Bus: t.Bus, Device: t.Device}, true
		}
	}
	return Addr{}, false
}
