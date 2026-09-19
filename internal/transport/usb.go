package transport

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/gousb"

	"goodix5120/internal/proto"
)

const (
	// VendorID and ProductID identify the Goodix 27c6:5120 sensor.
	VendorID  gousb.ID = 0x27c6
	ProductID gousb.ID = 0x5120

	// packetSize is the bulk endpoint wMaxPacketSize. Outbound frames are
	// zero-padded up to a multiple of this and written one packet at a time,
	// mirroring the reference pyusb implementation.
	packetSize = 0x40

	// readBufferSize is the ceiling on a single inbound transfer.
	readBufferSize = 0x10000
)

// ErrNotFound reports that no 27c6:5120 device is attached.
var ErrNotFound = errors.New("goodix 27c6:5120 sensor not found: no matching USB device is attached")

// ErrPermission reports that the device is attached but cannot be opened
// by the current user. There is no udev rule for this device, so this is the
// expected failure when not running as root.
var ErrPermission = errors.New("permission denied opening the goodix 27c6:5120 sensor: no udev rule grants access, so run this under sudo")

// usbTransport is a Transport backed by real hardware.
type usbTransport struct {
	sender

	ctx  *gousb.Context
	dev  *gousb.Device
	cfg  *gousb.Config
	intf *gousb.Interface
	in   *gousb.InEndpoint
	out  *gousb.OutEndpoint

	closeOnce sync.Once
	closeErr  error
}

// OpenUSB opens the sensor over USB and claims its bulk data interface.
func OpenUSB(opts Options) (Transport, error) {
	opts = opts.withDefaults()

	usbCtx := gousb.NewContext()

	dev, err := openDevice(usbCtx)
	if err != nil {
		usbCtx.Close()
		return nil, err
	}

	t := &usbTransport{ctx: usbCtx, dev: dev}
	t.sender = sender{opts: opts, write: t.writeFrame}

	// Auto-detach lets libusb steal the interface from any bound kernel driver
	// and hand it back on release.
	if err := dev.SetAutoDetach(true); err != nil {
		t.Close()
		return nil, fmt.Errorf("enabling kernel driver auto-detach: %w", err)
	}

	if err := t.claimDataInterface(); err != nil {
		t.Close()
		return nil, err
	}

	opts.logf("transport: opened %04x:%04x interface %d (in %s, out %s)",
		uint16(VendorID), uint16(ProductID), t.intf.Setting.Number, t.in.Desc.Address, t.out.Desc.Address)
	return t, nil
}

// openDevice finds and opens the sensor, distinguishing "not attached" from
// "attached but not permitted".
//
// gousb.OpenDevices reports a failed open through its error return while still
// returning an empty device slice, so an empty slice alone cannot be read as
// "not found". The opener callback runs before the open is attempted, so
// counting matches there tells us whether the device was present at all.
func openDevice(usbCtx *gousb.Context) (*gousb.Device, error) {
	matched := 0
	devs, err := usbCtx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		if desc.Vendor != VendorID || desc.Product != ProductID {
			return false
		}
		matched++
		return matched == 1 // open only the first match
	})

	if len(devs) > 0 {
		return devs[0], nil
	}

	switch {
	case matched == 0 || errors.Is(err, gousb.ErrorNoDevice):
		if err != nil {
			return nil, fmt.Errorf("%w (while enumerating: %v)", ErrNotFound, err)
		}
		return nil, ErrNotFound
	case errors.Is(err, gousb.ErrorAccess):
		return nil, fmt.Errorf("%w (libusb: %v)", ErrPermission, err)
	case err != nil:
		return nil, fmt.Errorf("opening goodix %04x:%04x: %w", uint16(VendorID), uint16(ProductID), err)
	default:
		return nil, ErrNotFound
	}
}

// claimDataInterface selects the CDC-Data (or vendor-specific) interface of the
// active config and resolves its bulk IN and OUT endpoints.
func (t *usbTransport) claimDataInterface() error {
	cfgNum, err := t.dev.ActiveConfigNum()
	if err != nil {
		return fmt.Errorf("reading active config number: %w", err)
	}
	cfg, err := t.dev.Config(cfgNum)
	if err != nil {
		return fmt.Errorf("claiming config %d: %w", cfgNum, err)
	}
	t.cfg = cfg

	setting, in, out, err := findDataInterface(cfg.Desc)
	if err != nil {
		return err
	}

	intf, err := cfg.Interface(setting.Number, setting.Alternate)
	if err != nil {
		return fmt.Errorf("claiming interface %d alt %d: %w", setting.Number, setting.Alternate, err)
	}
	t.intf = intf

	if t.in, err = intf.InEndpoint(in.Number); err != nil {
		return fmt.Errorf("opening bulk IN endpoint %s: %w", in.Address, err)
	}
	if t.out, err = intf.OutEndpoint(out.Number); err != nil {
		return fmt.Errorf("opening bulk OUT endpoint %s: %w", out.Address, err)
	}
	return nil
}

// findDataInterface searches a config for an interface whose class is CDC Data
// or vendor-specific and which exposes both a bulk IN and a bulk OUT endpoint.
// On the 27c6:5120 this is interface 1, with EP 0x83 IN and EP 0x01 OUT.
func findDataInterface(desc gousb.ConfigDesc) (gousb.InterfaceSetting, gousb.EndpointDesc, gousb.EndpointDesc, error) {
	for _, iface := range desc.Interfaces {
		for _, alt := range iface.AltSettings {
			if alt.Class != gousb.ClassData && alt.Class != gousb.ClassVendorSpec {
				continue
			}
			in, out, ok := bulkEndpoints(alt)
			if ok {
				return alt, in, out, nil
			}
		}
	}
	return gousb.InterfaceSetting{}, gousb.EndpointDesc{}, gousb.EndpointDesc{}, fmt.Errorf(
		"no usable interface in config %d: expected a CDC-Data (0x0a) or vendor-specific (0xff) interface with both a bulk IN and a bulk OUT endpoint", desc.Number)
}

// bulkEndpoints returns the bulk IN and OUT endpoints of a setting, if it has both.
func bulkEndpoints(alt gousb.InterfaceSetting) (in, out gousb.EndpointDesc, ok bool) {
	var haveIn, haveOut bool
	for _, ep := range alt.Endpoints {
		if ep.TransferType != gousb.TransferTypeBulk {
			continue
		}
		switch {
		case ep.Direction == gousb.EndpointDirectionIn && !haveIn:
			in, haveIn = ep, true
		case ep.Direction == gousb.EndpointDirectionOut && !haveOut:
			out, haveOut = ep, true
		}
	}
	return in, out, haveIn && haveOut
}

// writeFrame pads the frame to a multiple of the packet size and writes it in
// packet-sized chunks.
func (t *usbTransport) writeFrame(ctx context.Context, _ proto.Opcode, _, frame []byte) error {
	if t.out == nil {
		return errors.New("transport is closed")
	}

	padded := padFrame(frame)
	for off := 0; off < len(padded); off += packetSize {
		chunk := padded[off : off+packetSize]
		n, err := t.out.WriteContext(ctx, chunk)
		if err != nil {
			return fmt.Errorf("writing bytes %d..%d of %d to %s: %w", off, off+n, len(padded), t.out.Desc.Address, err)
		}
	}
	return nil
}

// padFrame zero-extends b to a multiple of packetSize.
func padFrame(b []byte) []byte {
	rem := len(b) % packetSize
	if rem == 0 && len(b) > 0 {
		return b
	}
	padded := make([]byte, len(b)+packetSize-rem)
	copy(padded, b)
	return padded
}

// Recv reads whatever the device has to offer. A short read is normal.
func (t *usbTransport) Recv(timeout time.Duration) ([]byte, error) {
	if t.in == nil {
		return nil, errors.New("transport is closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), t.resolveTimeout(timeout))
	defer cancel()

	buf := make([]byte, readBufferSize)
	n, err := t.in.ReadContext(ctx, buf)
	if err != nil && n == 0 {
		if ctx.Err() != nil || errors.Is(err, gousb.TransferTimedOut) {
			return nil, fmt.Errorf("reading from %s: %w", t.in.Desc.Address, ErrTimeout)
		}
		return nil, fmt.Errorf("reading from %s: %w", t.in.Desc.Address, err)
	}

	out := buf[:n]
	t.opts.logf("transport: RX %d bytes: %s", len(out), hex.EncodeToString(out))
	return out, nil
}

// Close releases the interface, config, device and libusb context, in that
// order. Repeat calls are no-ops that return the first result.
func (t *usbTransport) Close() error {
	t.closeOnce.Do(func() {
		var errs []error
		if t.intf != nil {
			t.intf.Close() // gousb: returns nothing
			t.intf, t.in, t.out = nil, nil, nil
		}
		if t.cfg != nil {
			if err := t.cfg.Close(); err != nil {
				errs = append(errs, fmt.Errorf("closing config: %w", err))
			}
			t.cfg = nil
		}
		if t.dev != nil {
			if err := t.dev.Close(); err != nil {
				errs = append(errs, fmt.Errorf("closing device: %w", err))
			}
			t.dev = nil
		}
		if t.ctx != nil {
			if err := t.ctx.Close(); err != nil {
				errs = append(errs, fmt.Errorf("closing usb context: %w", err))
			}
			t.ctx = nil
		}
		t.closeErr = errors.Join(errs...)
	})
	return t.closeErr
}
