package transport

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"testing"

	"goodix5120/internal/proto"
)

// helloRecord is a stand-in for the host's first handshake flight: a whole,
// well-formed TLS 1.2 handshake record. The body is filler — the gate checks
// framing, not content, and the real bodies are derived from the PSK.
func helloRecord(bodyLen int) []byte {
	rec := []byte{proto.TLSHandshake, 0x03, 0x03, byte(bodyLen >> 8), byte(bodyLen)}
	for i := range bodyLen {
		rec = append(rec, byte(i))
	}
	return rec
}

// TestSendTLSIsClosedByDefault is the central rule for the new path: a caller
// that has not deliberately opened it cannot put opaque bytes on the wire. The
// ceiling and the payload rules cannot help here — a TLS-data pack has no
// opcode — so this switch is the whole gate for direction host → device.
func TestSendTLSIsClosedByDefault(t *testing.T) {
	s, w := newStubTransport(Options{}) // zero value: ClassSafe, TLS path closed

	err := s.SendTLS(helloRecord(16))
	if err == nil {
		t.Fatal("SendTLS succeeded with Options.AllowTLSData unset")
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("SendTLS = %v, want an error wrapping ErrRefused", err)
	}
	if len(w.frames) != 0 {
		t.Fatalf("a refused TLS pack still reached the writer: %x", w.frames)
	}
}

// TestSendTLSWrapsRecordsInATLSDataPack checks the framing the device expects:
// pack flag 0xb0, the records verbatim as the pack payload, and no message
// layer in between (docs/protocol.md, "TLS").
func TestSendTLSWrapsRecordsInATLSDataPack(t *testing.T) {
	s, w := newStubTransport(Options{AllowTLSData: true})

	rec := helloRecord(47) // the length of the EC's own ClientHello
	if err := s.SendTLS(rec); err != nil {
		t.Fatalf("SendTLS = %v, want nil", err)
	}
	if len(w.frames) != 1 {
		t.Fatalf("writer saw %d frames, want 1", len(w.frames))
	}
	if !w.tls[0] {
		t.Error("the writer was not told this was TLS data")
	}

	flags, payload, err := proto.DecodePack(w.frames[0])
	if err != nil {
		t.Fatalf("the transmitted pack does not decode: %v", err)
	}
	if flags != proto.FlagTLSData {
		t.Errorf("pack flags = 0x%02x, want 0x%02x (FlagTLSData)", flags, proto.FlagTLSData)
	}
	if !bytes.Equal(payload, rec) {
		t.Errorf("pack payload does not match the record handed in")
	}
}

// TestSendTLSRefusesRecordsThatAreNotWhole is the TLS-layer analogue of the
// payload rules. An 0xe4 whose argument was missing wedged the EC three times;
// half a TLS record is the same shape of mistake, so it never reaches the wire.
func TestSendTLSRefusesRecordsThatAreNotWhole(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"header only", helloRecord(16)[:5]},
		{"body one byte short", helloRecord(16)[:20]},
		{"a Goodix command pack mistaken for TLS", proto.Encode(0xa8, []byte{0x00, 0x00})},
		{"a whole record with junk appended", append(helloRecord(4), 0xff)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, w := newStubTransport(Options{AllowTLSData: true})
			err := s.SendTLS(tc.in)
			if err == nil {
				t.Fatalf("SendTLS(% x) was permitted", tc.in)
			}
			if !errors.Is(err, ErrRefused) {
				t.Errorf("SendTLS = %v, want an error wrapping ErrRefused", err)
			}
			if len(w.frames) != 0 {
				t.Errorf("a refused TLS pack reached the writer")
			}
		})
	}
}

// TestSendTLSAcceptsAWholeFlight allows several records in one pack. Whether the
// EC wants a server flight as one pack or as one pack per record is unverified
// (PLAN.md Phase 5b), so the gate refuses only what is certainly wrong — a
// partial record — and leaves the grouping to the bridge.
func TestSendTLSAcceptsAWholeFlight(t *testing.T) {
	s, w := newStubTransport(Options{AllowTLSData: true})

	ccs := []byte{proto.TLSChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}
	flight := append(append([]byte{}, ccs...), helloRecord(32)...)
	if err := s.SendTLS(flight); err != nil {
		t.Fatalf("SendTLS(two records) = %v, want nil", err)
	}
	if len(w.frames) != 1 {
		t.Fatalf("writer saw %d frames, want 1", len(w.frames))
	}
}

// TestSendTLSNeverLogsARecordBody is secret hygiene, the same rule the OTP and
// the 0xe4 reply are held to. A TLS body from this device is a fingerprint
// image; the host's own records are derived from the PSK. Verbose mode may
// report a record's type and length and nothing else.
func TestSendTLSNeverLogsARecordBody(t *testing.T) {
	var buf bytes.Buffer
	s, _ := newStubTransport(Options{
		AllowTLSData: true,
		Verbose:      true,
		Logger:       log.New(&buf, "", 0),
	})

	body := bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 8)
	rec := append([]byte{proto.TLSApplicationData, 0x03, 0x03, 0x00, byte(len(body))}, body...)
	if err := s.SendTLS(rec); err != nil {
		t.Fatalf("SendTLS = %v", err)
	}

	logged := buf.String()
	if strings.Contains(logged, hex.EncodeToString(body)) || strings.Contains(logged, "deadbeef") {
		t.Fatalf("the record body was written to the log:\n%s", logged)
	}
	for _, want := range []string{"application data", "TLS 1.2", "32-byte body"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log does not mention %q; it should still say what went out:\n%s", want, logged)
		}
	}
}

// TestReplayDistinguishesCommandsFromTLSData keeps an offline rehearsal honest.
// A script that expects a command must not be satisfied by TLS data, or the
// rehearsal would pass while the bridge sent the wrong thing.
func TestReplayDistinguishesCommandsFromTLSData(t *testing.T) {
	opts := Options{AllowTLSData: true}

	tr := NewReplay([]Exchange{{Cmd: 0xa8, Payload: []byte{0x00, 0x00}}}, opts)
	defer tr.Close()
	if err := tr.SendTLS(helloRecord(8)); err == nil {
		t.Error("SendTLS satisfied a script expecting firmware_version")
	}

	tr2 := NewReplay([]Exchange{{TLS: true}}, opts)
	defer tr2.Close()
	if err := tr2.Send(0xa8, []byte{0x00, 0x00}); err == nil {
		t.Error("Send satisfied a script expecting TLS data")
	}
}

// TestReplayScriptsTLSExchanges covers the path the bridge rehearsal uses: a
// scripted TLS send, checked by length, answering with the device's records.
func TestReplayScriptsTLSExchanges(t *testing.T) {
	rec := helloRecord(12)
	answer := proto.EncodePack(proto.FlagTLSData, helloRecord(20))

	tr := NewReplay([]Exchange{{TLS: true, Payload: rec, Responses: [][]byte{answer}}},
		Options{AllowTLSData: true})
	defer tr.Close()

	if err := tr.SendTLS(rec); err != nil {
		t.Fatalf("SendTLS against a scripted TLS exchange = %v", err)
	}
	got, err := tr.Recv(0)
	if err != nil {
		t.Fatalf("Recv = %v", err)
	}
	if !bytes.Equal(got, answer) {
		t.Errorf("Recv returned %x, want the scripted pack", got)
	}

	// A different number of record bytes must fail: the script pins what the
	// bridge sends, even though it cannot pin the ciphertext itself.
	tr3 := NewReplay([]Exchange{{TLS: true, Payload: rec}}, Options{AllowTLSData: true})
	defer tr3.Close()
	if err := tr3.SendTLS(helloRecord(13)); err == nil {
		t.Error("a TLS send of the wrong length satisfied the script")
	}
}
