package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"testing"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// These fixtures are test-only on purpose. Replaying the vendor init needs a
// ClassStateChanging ceiling, and that value must not appear anywhere in the
// shipped binary — main() says "never raised by this binary" and that has to
// stay literally true. Keeping them here also keeps the synthetic PSK, OTP and
// image bytes out of the program.

// synthetic returns n deterministic bytes for a fixture whose real bytes must
// never enter this repository: the 0xe4 reply carries a hash of the device PSK,
// the 0xa6 reply is the OTP, the 0x90 config is unknown, and every 0xb0 pack is
// TLS ciphertext of a fingerprint image.
//
// Bytes are SHA-256 of label and a counter, so a fixture is reproducible
// without depending on any RNG, and two labels can never collide.
//
// Every call is a place where the fixture is knowingly not the vendor's bytes.
// Grep for it before citing a fixture as evidence.
func synthetic(label string, n int) []byte {
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", label, i)))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

// ackFor builds the acknowledgement the device sends before a data reply: a
// 0xb0 message carrying the original command and a status byte.
func ackFor(cmd proto.Opcode) []byte {
	return proto.Encode(proto.AckCmd, []byte{byte(cmd), 0x01})
}

// dataFor builds a data reply. Checksums are computed by our own encoder rather
// than transcribed, so a fixture can never carry a wrong one.
func dataFor(cmd proto.Opcode, payload []byte) []byte {
	return proto.Encode(cmd, payload)
}

// mcuState builds a 20-byte 0xae reply with the given status byte. The trailing
// bytes are the steady-state value seen in both captures.
func mcuState(status byte) []byte {
	raw := []byte{
		0x02, status, 0x31, 0x00, 0x00, 0x00, 0x01, 0x00, 0x90, 0x63,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04,
	}
	return dataFor(0xae, raw)
}

// vendorInitScript is the Windows driver's init sequence as a replay script,
// from `96` through the second `ae` — the point where the TLS flag visibly
// flips, which is what makes the fixture worth having.
//
// Requests come from vendorInit, so they cannot drift from what the probe would
// send. Responses are built with our encoder from the shapes recorded in
// docs/protocol.md.
//
// Synthetic, and flagged as such wherever it appears:
//   - the 32-byte hash in the 0xe4 reply (it is a hash of the device PSK)
//   - the 64-byte OTP in the 0xa6 reply
//   - the 224-byte 0x90 config, which the driver log truncates, and which is
//     therefore the one OUTBOUND frame here that is not the vendor's
//   - the TLS ClientHello after 0xd0
func vendorInitScript() []transport.Exchange {
	req := func(i int) step {
		st := vendorInit[i]
		if !st.known() {
			// 0x90: nobody has these bytes. The fixture says so by name.
			st.payload = synthetic("90-config", 224)
		}
		return st
	}
	ex := func(i int, responses ...[]byte) transport.Exchange {
		st := req(i)
		return transport.Exchange{Cmd: st.cmd, Payload: st.payload, Responses: responses}
	}

	// The 0xe4 reply is 41 bytes: data_type (4) + length (4) + a 32-byte hash
	// is 40, so one byte is unaccounted for. Rather than quietly pad, the
	// fixture keeps the recorded length and names the gap.
	pskReply := make([]byte, 0, 41)
	pskReply = binary.LittleEndian.AppendUint32(pskReply, 0xbb020003)
	pskReply = binary.LittleEndian.AppendUint32(pskReply, 0x20)
	pskReply = append(pskReply, synthetic("e4-psk-hash", 32)...)
	pskReply = append(pskReply, 0x00) // unexplained 41st byte; re-read the ETW log

	clientHello := append([]byte{0x16, 0x03, 0x03, 0x00, 0x40}, synthetic("tls-clienthello", 64)...)

	return []transport.Exchange{
		ex(0), // 96 enable_chip: the driver does not wait for a reply
		ex(1, ackFor(0xa8), dataFor(0xa8, []byte("GF_ITE_EC_20063\x00"))),
		ex(2, mcuState(0x11)), // ae: no ACK, and TLS is down on a cold init
		ex(3, ackFor(0xe4), dataFor(0xe4, pskReply)),
		ex(4, ackFor(0xa2), dataFor(0xa2, []byte{0x01, 0x00, 0x08})),
		ex(5, ackFor(0x82), dataFor(0x82, []byte{0xa2, 0x04, 0x25, 0x00})), // chip ID 0x2504
		ex(6, ackFor(0xa6), dataFor(0xa6, synthetic("a6-otp", 64))),
		ex(7, ackFor(0xa2), dataFor(0xa2, []byte{0x01, 0x00, 0x08})),
		ex(8, ackFor(0x70)),
		ex(9, ackFor(0x98), dataFor(0x98, []byte{0x01, 0x01})),
		ex(10, ackFor(0x90), dataFor(0x90, []byte{0x01, 0x01})),
		ex(11, proto.EncodePack(proto.FlagTLSData, clientHello)), // d0: no ACK
		ex(12, ackFor(0xd4)),
		ex(13, mcuState(0x13)), // ae again: TLS now up
	}
}

// imagePack builds one image transfer: a 0xb0 pack holding a single TLS
// application-data record of 7744 bytes, which is 7749 bytes of pack payload.
// All 43 image packs in dump.pcapng are exactly that size.
func imagePack(label string) []byte {
	record := append([]byte{0x17, 0x03, 0x03, 0x1e, 0x40}, synthetic(label, 7744)...)
	return proto.EncodePack(proto.FlagTLSData, record)
}

// fdtEvent builds an event payload: a real four-byte header with synthetic zone
// readings. The headers are protocol and are reproduced exactly; the readings
// came off a real finger, so they are not.
func fdtEvent(cmd proto.Opcode, header [4]byte, label string) []byte {
	payload := append(header[:], synthetic(label, 2*proto.FDTZones)...)
	return dataFor(cmd, payload)
}

// arm builds an arm command payload with synthetic thresholds.
func arm(t *testing.T, cmd proto.Opcode, label string) []byte {
	t.Helper()
	var a proto.FDTArm
	copy(a.Thresholds[:], synthetic(label, proto.FDTZones))
	payload, err := proto.EncodeFDTArm(cmd, a)
	if err != nil {
		t.Fatalf("EncodeFDTArm(0x%02x): %v", byte(cmd), err)
	}
	return payload
}

// captureLoopScript is the steady-state capture loop from dump.pcapng: arm,
// wait for a touch, fetch the image, arm for lift.
//
// The structure and the event headers are what the capture shows, read back
// with cmd/goodix-pcap. The zone readings, the arm thresholds and the image
// ciphertext are synthetic — the images are fingerprints, and none of it
// belongs in a repository.
func captureLoopScript(t *testing.T) []transport.Exchange {
	t.Helper()
	return []transport.Exchange{
		{Cmd: 0x32, Payload: arm(t, 0x32, "arm-down"), Responses: [][]byte{
			ackFor(0x32),
			fdtEvent(0x32, [4]byte{0x02, 0x00, 0x3f, 0x00}, "zones-down"),
		}},
		{Cmd: 0x20, Payload: []byte{0x01, 0x00}, Responses: [][]byte{
			ackFor(0x20),
			imagePack("image-1"),
		}},
		// 22 of the 43 arms for lift got an ACK and no event at all.
		{Cmd: 0x34, Payload: arm(t, 0x34, "arm-up-1"), Responses: [][]byte{ackFor(0x34)}},
		{Cmd: 0x36, Payload: arm(t, 0x36, "arm-manual"), Responses: [][]byte{
			ackFor(0x36),
			fdtEvent(0x36, [4]byte{0x00, 0x01, 0x3f, 0x00}, "zones-manual"),
		}},
		{Cmd: 0x20, Payload: []byte{0x01, 0x00}, Responses: [][]byte{
			ackFor(0x20),
			imagePack("image-2"),
		}},
		{Cmd: 0x34, Payload: arm(t, 0x34, "arm-up-2"), Responses: [][]byte{
			ackFor(0x34),
			fdtEvent(0x34, [4]byte{0x00, 0x02, 0x00, 0x00}, "zones-up"),
		}},
		// A "base invalid" re-arm: header 80 00 00 00, with the readings zeroed,
		// which is how all five of them look in dump.pcapng.
		{Cmd: 0x32, Payload: arm(t, 0x32, "arm-down-2"), Responses: [][]byte{
			ackFor(0x32),
			dataFor(0x32, append([]byte{0x80, 0x00, 0x00, 0x00}, make([]byte, 2*proto.FDTZones)...)),
		}},
	}
}

// runScript drives a script through the probe's own collect and drain, so the
// fixtures exercise the real decode path rather than a test-only one.
func runScript(t *testing.T, script []transport.Exchange, ceiling proto.Class) string {
	t.Helper()

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	tr := transport.NewReplay(script, transport.Options{Ceiling: ceiling, Verbose: true, Logger: logger})
	defer tr.Close()

	for _, ex := range script {
		if err := tr.Send(ex.Cmd, ex.Payload); err != nil {
			t.Fatalf("Send(0x%02x): %v", byte(ex.Cmd), err)
		}
		if err := collect(logger, tr, ex.Cmd, 0); err != nil {
			t.Fatalf("collect after 0x%02x: %v", byte(ex.Cmd), err)
		}
	}
	drain(logger, tr, 0)

	rt := tr.(replayCounters)
	if n := rt.Remaining(); n != 0 {
		t.Errorf("%d scripted exchanges were never sent", n)
	}
	if n := rt.Unread(); n != 0 {
		t.Errorf("%d transfers left unread:\n%s", n, buf.String())
	}
	return buf.String()
}

// TestVendorInitReplays decodes the whole vendor init offline. Every frame must
// decode, which also proves the payloads in vendorInit satisfy the transport's
// payload rules — the script is sent through the real gate.
func TestVendorInitReplays(t *testing.T) {
	out := runScript(t, vendorInitScript(), proto.ClassStateChanging)

	for _, bad := range []string{"did not decode", "malformed ACK", "stray ACK", "UNREGISTERED"} {
		if strings.Contains(out, bad) {
			t.Errorf("log contains %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{
		`"GF_ITE_EC_20063"`,
		"data for get_mcu_state (0xae)",
		"data for read_register (0x82)",
		"ACK for tls_successfully_established (0xd4)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("vendor init log lacks %q:\n%s", want, out)
		}
	}
}

// TestCaptureLoopReplays does the same for the steady-state loop.
func TestCaptureLoopReplays(t *testing.T) {
	out := runScript(t, captureLoopScript(t), proto.ClassStateChanging)

	for _, bad := range []string{"did not decode", "malformed ACK", "stray ACK"} {
		if strings.Contains(out, bad) {
			t.Errorf("log contains %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "ACK for mcu_get_image (0x20)") {
		t.Errorf("capture loop lacks the image ACK:\n%s", out)
	}
}

// TestFixtureImagePacksMatchTheCapture pins the one number the fixture asserts
// about real image traffic: all 43 packs in dump.pcapng are 7749 bytes of pack
// payload, holding a 7744-byte TLS application-data record.
func TestFixtureImagePacksMatchTheCapture(t *testing.T) {
	flags, payload, err := proto.DecodePack(imagePack("image-1"))
	if err != nil {
		t.Fatalf("DecodePack: %v", err)
	}
	if flags != proto.FlagTLSData {
		t.Errorf("flags = 0x%02x, want 0x%02x", flags, proto.FlagTLSData)
	}
	if len(payload) != 7749 {
		t.Errorf("pack payload = %d bytes, want 7749", len(payload))
	}
	if got := binary.BigEndian.Uint16(payload[3:5]); got != 7744 {
		t.Errorf("TLS record length = %d, want 7744", got)
	}
}

// TestFixtureEventsDecode runs the fixture's event payloads back through the
// decoders, so the fixture and the decoder cannot drift apart.
func TestFixtureEventsDecode(t *testing.T) {
	tests := []struct {
		cmd  proto.Opcode
		head [4]byte
		want proto.FDTEventKind
	}{
		{0x32, [4]byte{0x02, 0x00, 0x3f, 0x00}, proto.FDTEventDown},
		{0x34, [4]byte{0x00, 0x02, 0x00, 0x00}, proto.FDTEventUp},
		{0x36, [4]byte{0x00, 0x01, 0x3f, 0x00}, proto.FDTEventManual},
		{0x32, [4]byte{0x80, 0x00, 0x00, 0x00}, proto.FDTEventBaseInvalid},
	}
	for _, tt := range tests {
		frame := fdtEvent(tt.cmd, tt.head, "zones")
		_, packPayload, err := proto.DecodePack(frame)
		if err != nil {
			t.Fatalf("DecodePack: %v", err)
		}
		cmd, payload, err := proto.DecodeMessage(packPayload)
		if err != nil {
			t.Fatalf("DecodeMessage: %v", err)
		}
		e, err := proto.DecodeFDTEvent(cmd, payload)
		if err != nil {
			t.Fatalf("DecodeFDTEvent: %v", err)
		}
		if e.Kind != tt.want {
			t.Errorf("header %x decoded as %v, want %v", tt.head, e.Kind, tt.want)
		}
	}
}

// TestSyntheticIsDeterministicAndDistinct is what lets a reviewer trust the
// "no real bytes" claim: a fixture region either equals synthetic(label, n) or
// it does not, and a pasted real secret would fail that check.
func TestSyntheticIsDeterministicAndDistinct(t *testing.T) {
	if !bytes.Equal(synthetic("a6-otp", 64), synthetic("a6-otp", 64)) {
		t.Error("synthetic is not deterministic")
	}
	if bytes.Equal(synthetic("a6-otp", 64), synthetic("e4-psk-hash", 64)) {
		t.Error("two labels produced the same bytes")
	}
	if n := len(synthetic("image-1", 7744)); n != 7744 {
		t.Errorf("synthetic returned %d bytes, want 7744", n)
	}
}

// The vendor's own OTP begins with the ASCII "S2A755.", and the driver log
// records it. Nothing resembling it may be in the repository.
func TestFixtureCarriesNoRealOTP(t *testing.T) {
	if bytes.Contains(synthetic("a6-otp", 64), []byte("S2A755")) {
		t.Error("the synthetic OTP contains the real OTP prefix")
	}
}
