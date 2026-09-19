package transport

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/gousb"

	"goodix5120/internal/proto"
)

// realConfigDesc mirrors the descriptor read from the target machine with
// `lsusb -v`: two interfaces, the CDC control one carrying a single interrupt
// IN endpoint and the CDC data one carrying the bulk pair we want.
func realConfigDesc() gousb.ConfigDesc {
	return gousb.ConfigDesc{
		Number: 1,
		Interfaces: []gousb.InterfaceDesc{
			{
				Number: 0,
				AltSettings: []gousb.InterfaceSetting{{
					Number: 0,
					Class:  gousb.ClassComm,
					Endpoints: map[gousb.EndpointAddress]gousb.EndpointDesc{
						0x82: {Address: 0x82, Number: 2, Direction: gousb.EndpointDirectionIn, MaxPacketSize: 8, TransferType: gousb.TransferTypeInterrupt},
					},
				}},
			},
			{
				Number: 1,
				AltSettings: []gousb.InterfaceSetting{{
					Number: 1,
					Class:  gousb.ClassData,
					Endpoints: map[gousb.EndpointAddress]gousb.EndpointDesc{
						0x01: {Address: 0x01, Number: 1, Direction: gousb.EndpointDirectionOut, MaxPacketSize: 64, TransferType: gousb.TransferTypeBulk},
						0x83: {Address: 0x83, Number: 3, Direction: gousb.EndpointDirectionIn, MaxPacketSize: 64, TransferType: gousb.TransferTypeBulk},
					},
				}},
			},
		},
	}
}

func TestFindDataInterfacePicksTheBulkPair(t *testing.T) {
	setting, in, out, err := findDataInterface(realConfigDesc())
	if err != nil {
		t.Fatalf("findDataInterface: %v", err)
	}
	if setting.Number != 1 {
		t.Errorf("interface = %d, want 1", setting.Number)
	}
	if in.Address != 0x83 {
		t.Errorf("IN endpoint = %s, want 0x83", in.Address)
	}
	if out.Address != 0x01 {
		t.Errorf("OUT endpoint = %s, want 0x01", out.Address)
	}
}

func TestFindDataInterfaceAcceptsVendorSpecific(t *testing.T) {
	desc := realConfigDesc()
	desc.Interfaces[1].AltSettings[0].Class = gousb.ClassVendorSpec

	setting, _, _, err := findDataInterface(desc)
	if err != nil {
		t.Fatalf("vendor-specific interface should be accepted: %v", err)
	}
	if setting.Number != 1 {
		t.Errorf("interface = %d, want 1", setting.Number)
	}
}

func TestFindDataInterfaceRejectsIncompleteDescriptors(t *testing.T) {
	t.Run("no data interface", func(t *testing.T) {
		desc := realConfigDesc()
		desc.Interfaces = desc.Interfaces[:1] // CDC control only
		if _, _, _, err := findDataInterface(desc); err == nil {
			t.Fatal("expected an error when no data interface exists")
		}
	})

	t.Run("missing bulk out", func(t *testing.T) {
		desc := realConfigDesc()
		delete(desc.Interfaces[1].AltSettings[0].Endpoints, 0x01)
		if _, _, _, err := findDataInterface(desc); err == nil {
			t.Fatal("expected an error when the bulk OUT endpoint is missing")
		}
	})

	t.Run("endpoints are not bulk", func(t *testing.T) {
		desc := realConfigDesc()
		for addr, ep := range desc.Interfaces[1].AltSettings[0].Endpoints {
			ep.TransferType = gousb.TransferTypeInterrupt
			desc.Interfaces[1].AltSettings[0].Endpoints[addr] = ep
		}
		if _, _, _, err := findDataInterface(desc); err == nil {
			t.Fatal("expected an error when no bulk endpoints exist")
		}
	})
}

func TestPadFrame(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int
	}{
		{0, 64}, {1, 64}, {63, 64}, {64, 64}, {65, 128}, {128, 128}, {129, 192},
	} {
		got := padFrame(bytes.Repeat([]byte{0xaa}, tc.in))
		if len(got) != tc.want {
			t.Errorf("padFrame(%d bytes) length = %d, want %d", tc.in, len(got), tc.want)
		}
		if len(got)%packetSize != 0 {
			t.Errorf("padFrame(%d bytes) length %d is not a multiple of %d", tc.in, len(got), packetSize)
		}
		// Original content must survive, and the tail must be zeroes.
		if !bytes.Equal(got[:tc.in], bytes.Repeat([]byte{0xaa}, tc.in)) {
			t.Errorf("padFrame(%d bytes) corrupted the payload", tc.in)
		}
		if !bytes.Equal(got[tc.in:], make([]byte, len(got)-tc.in)) {
			t.Errorf("padFrame(%d bytes) padded with non-zero bytes: %x", tc.in, got[tc.in:])
		}
	}
}

// The probe calls Send with a nil payload; it must be treated like an empty one
// on both transports.
func TestNilPayloadIsAccepted(t *testing.T) {
	s, w := newStubTransport(Options{})
	if err := s.Send(opNOP, nil); err != nil {
		t.Fatalf("Send with nil payload: %v", err)
	}
	if want := proto.Encode(opNOP, nil); !bytes.Equal(w.frames[0], want) {
		t.Errorf("frame = %x, want %x", w.frames[0], want)
	}
	if len(padFrame(w.frames[0]))%packetSize != 0 {
		t.Error("a nil-payload frame does not pad to a whole packet")
	}

	tr := NewReplay([]Exchange{{Cmd: opNOP, Payload: []byte{}}}, Options{})
	defer tr.Close()
	if err := tr.Send(opNOP, nil); err != nil {
		t.Fatalf("replay Send with nil payload against an empty scripted payload: %v", err)
	}
	if _, err := tr.Recv(0); !errors.Is(err, ErrTimeout) {
		t.Errorf("replay Recv after a silent exchange = %v, want ErrTimeout", err)
	}
}

// The exported sentinels are the probe's classification hooks.
func TestErrorSentinelsAreDistinct(t *testing.T) {
	if errors.Is(ErrNotFound, ErrPermission) || errors.Is(ErrPermission, ErrNotFound) {
		t.Fatal("ErrNotFound and ErrPermission must be distinguishable")
	}

	wrappedPerm := errors.Join(nil, ErrPermission)
	if !errors.Is(wrappedPerm, ErrPermission) {
		t.Error("wrapped ErrPermission does not satisfy errors.Is")
	}

	if err := checkOpcode(opReset, proto.ClassSafe, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("ceiling refusal %v does not wrap ErrRefused", err)
	}
	if err := checkOpcode(opUnknwn, proto.ClassDestructive, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("unregistered refusal %v does not wrap ErrRefused", err)
	}

	s, _ := newStubTransport(Options{})
	if err := s.Send(opReset, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("Send refusal %v does not wrap ErrRefused", err)
	}
	tr := NewReplay([]Exchange{{Cmd: opReset}}, Options{})
	defer tr.Close()
	if err := tr.Send(opReset, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("replay Send refusal %v does not wrap ErrRefused", err)
	}
}
