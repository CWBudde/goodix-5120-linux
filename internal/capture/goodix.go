package capture

import (
	"fmt"

	"goodix5120/internal/proto"
)

// Frame is one Goodix pack seen on the wire, decoded as far as it can be.
type Frame struct {
	In      bool   // true if the device sent it
	Flags   byte   // pack flags: 0xa0 message, 0xb0/0xb2 TLS
	Pack    []byte // the pack payload, with USB padding removed
	Cmd     proto.Opcode
	Payload []byte // message payload, when Flags is 0xa0
	// Ack is set when the frame is a 0xb0 ACK message, in which case Cmd is the
	// command being acknowledged and Status is its status byte.
	Ack    bool
	Status byte
	// Err records why decoding stopped, if it did. A frame with Err set is
	// still reported: a frame that will not decode is itself a finding.
	Err error
}

// TLS reports whether the pack carries a TLS record rather than a message.
func (f Frame) TLS() bool { return f.Flags == proto.FlagTLSData || f.Flags == proto.FlagTLSAlt }

// Frames decodes the Goodix bulk traffic of one device.
//
// Outbound transfers are padded to 64 bytes by the host, and the vendor driver
// does not zero that padding — uninitialised Windows kernel stack memory rides
// along after the pack. Everything past the declared pack length is therefore
// dropped here and never decoded or emitted, which is both a correctness rule
// and the first line of the scrubbing.
func Frames(ts []Transfer, dev Addr) []Frame {
	var out []Frame
	for _, t := range ts {
		if t.Bus != dev.Bus || t.Device != dev.Device || t.Transfer != transferBulk || len(t.Data) == 0 {
			continue
		}

		f := Frame{In: t.In}
		flags, packPayload, err := proto.DecodePack(t.Data)
		if err != nil {
			f.Err = fmt.Errorf("pack: %w", err)
			out = append(out, f)
			continue
		}
		f.Flags = flags
		f.Pack = packPayload

		if f.TLS() {
			out = append(out, f)
			continue
		}

		cmd, payload, err := proto.DecodeMessage(packPayload)
		if err != nil {
			f.Err = fmt.Errorf("message: %w", err)
			out = append(out, f)
			continue
		}
		f.Cmd, f.Payload = cmd, payload

		if cmd == proto.AckCmd {
			acked, status, err := proto.DecodeAck(cmd, payload)
			if err != nil {
				f.Err = fmt.Errorf("ack: %w", err)
			} else {
				f.Ack, f.Cmd, f.Status, f.Payload = true, acked, status, nil
			}
		}
		out = append(out, f)
	}
	return out
}

// Summary counts what a capture contains without reproducing any of its bytes.
// It is what to look at first when exploring a new capture: it cannot leak a
// PSK hash, an OTP or a fingerprint image, because it holds no payloads.
type Summary struct {
	Transfers  int
	Frames     int
	Decoded    int
	Failed     int
	TXCommands map[proto.Opcode]int
	RXMessages map[proto.Opcode]int
	Acks       map[proto.Opcode]int
	TLSPacks   int
	TLSLengths map[int]int
	// PayloadLengths records, per outbound opcode, the payload lengths seen.
	// This is how a payload rule gets evidence without anyone reading bytes.
	PayloadLengths map[proto.Opcode]map[int]int
}

// Summarise reduces frames to counts.
func Summarise(frames []Frame, transfers int) Summary {
	s := Summary{
		Transfers:      transfers,
		Frames:         len(frames),
		TXCommands:     map[proto.Opcode]int{},
		RXMessages:     map[proto.Opcode]int{},
		Acks:           map[proto.Opcode]int{},
		TLSLengths:     map[int]int{},
		PayloadLengths: map[proto.Opcode]map[int]int{},
	}
	for _, f := range frames {
		if f.Err != nil {
			s.Failed++
			continue
		}
		s.Decoded++

		switch {
		case f.TLS():
			s.TLSPacks++
			s.TLSLengths[len(f.Pack)]++
		case f.Ack:
			s.Acks[f.Cmd]++
		case f.In:
			s.RXMessages[f.Cmd]++
		default:
			s.TXCommands[f.Cmd]++
			if s.PayloadLengths[f.Cmd] == nil {
				s.PayloadLengths[f.Cmd] = map[int]int{}
			}
			s.PayloadLengths[f.Cmd][len(f.Payload)]++
		}
	}
	return s
}
