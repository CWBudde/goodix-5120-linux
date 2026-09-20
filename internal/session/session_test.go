package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log"
	"os/exec"
	"strings"
	"testing"
	"time"

	"goodix5120/internal/image"
	"goodix5120/internal/proto"
	"goodix5120/internal/tlspsk"
	"goodix5120/internal/transport"
)

// These tests rehearse the Phase 5b bridge with no hardware attached. The
// "device" is LoopbackEC — an openssl s_client dressed in Goodix framing — so
// the TLS bytes are real, produced by a real implementation, and nothing about
// the handshake is invented. What they cannot tell us is anything about the EC
// itself; see the LoopbackEC doc comment.
//
// Every key here is a throwaway test key. The recovered device PSK lives only in
// gitignored captures/ and never appears in this repository.

func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(tlspsk.DefaultOpenSSL); err != nil {
		t.Skipf("openssl not on PATH: %v", err)
	}
}

// testPSK returns a throwaway 32-byte key whose every byte is fill.
func testPSK(fill byte) []byte {
	b := make([]byte, tlspsk.PSKLen)
	for i := range b {
		b[i] = fill
	}
	return b
}

// rig is a bridge wired to a loopback stand-in, with the log captured so the
// tests can assert on what was and was not written to it.
type rig struct {
	bridge *Bridge
	ec     *LoopbackEC
	tr     transport.Transport
	sess   *tlspsk.Session
	log    *bytes.Buffer
}

func newRig(t *testing.T, devicePSK, hostPSK []byte) *rig {
	t.Helper()
	requireOpenSSL(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sess, err := tlspsk.Start(ctx, tlspsk.Config{PSK: hostPSK, Port: -1})
	if err != nil {
		t.Fatalf("starting the host endpoint: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	logBuf := &bytes.Buffer{}
	logger := log.New(logBuf, "", 0)

	ec, err := StartLoopbackEC(ctx, LoopbackConfig{PSK: devicePSK, Logger: logger})
	if err != nil {
		t.Fatalf("starting the loopback EC: %v", err)
	}
	t.Cleanup(func() { _ = ec.Close() })

	// The rehearsal transport is a gated one: transport.NewPeer puts the same
	// safety gate in front of the stand-in that the USB path has.
	// 0xd0 is admitted, and nothing else above the safe ceiling: that is exactly
	// what `--tls --allow-d0` gives the live run.
	tr := transport.NewPeer(ec, transport.Options{
		AllowTLSData: true,
		Allow:        []proto.Opcode{opRequestTLSConnection},
		Timeout:      2 * time.Second,
		Logger:       logger,
	})
	t.Cleanup(func() { _ = tr.Close() })

	b := New(tr, sess, Options{
		Logger:           logger,
		DeviceTimeout:    200 * time.Millisecond,
		HandshakeTimeout: 20 * time.Second,
	})
	return &rig{bridge: b, ec: ec, tr: tr, sess: sess, log: logBuf}
}

// requestTLS sends 0xd0, which is what makes the stand-in open a session, just
// as it is what makes the EC start a handshake. Handshake must not be called
// before it: there would be no ClientHello to read.
func (r *rig) requestTLS(t *testing.T) {
	t.Helper()
	if err := r.tr.Send(opRequestTLSConnection, []byte{0x00, 0x00}); err != nil {
		t.Fatalf("Send(0xd0) = %v", err)
	}
}

// TestBridgeCompletesHandshakeWithMatchingPSK is the rehearsal of Phase 5b's
// success case: the EC's records go to the host, the host's go back, and the
// host's ChangeCipherSpec plus Finished is what says the two ends derived the
// same keys.
func TestBridgeCompletesHandshakeWithMatchingPSK(t *testing.T) {
	psk := testPSK(0x5a)
	r := newRig(t, psk, psk)
	r.requestTLS(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.bridge.Handshake(ctx); err != nil {
		t.Fatalf("Handshake with a matching PSK = %v\nlog:\n%s", err, r.log)
	}
	if !r.bridge.Done() {
		t.Error("Handshake returned nil but Done() is false")
	}
	toHost, toDevice := r.bridge.Counts()
	if toHost == 0 || toDevice == 0 {
		t.Errorf("records forwarded: %d to the host, %d to the device; both must be non-zero", toHost, toDevice)
	}
}

// TestBridgeReportsPSKMismatch is the rehearsal of the failure Phase 5b might
// actually hit: the recovered PSK is not the one the EC holds. The bridge must
// say so rather than hang, because which error comes out of Handshake is the
// entire result of that step.
func TestBridgeReportsPSKMismatch(t *testing.T) {
	r := newRig(t, testPSK(0x11), testPSK(0x22))
	r.requestTLS(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := r.bridge.Handshake(ctx)
	if err == nil {
		t.Fatalf("Handshake with mismatched keys succeeded\nlog:\n%s", r.log)
	}
	if errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("Handshake timed out instead of reporting the rejection: %v\nlog:\n%s", err, r.log)
	}
	if !errors.Is(err, ErrAlert) {
		// Not a failure in itself — openssl might drop the connection rather
		// than alert — but it is worth seeing which it was.
		t.Logf("mismatched keys failed without a TLS alert: %v", err)
		return
	}
	if !errors.Is(err, ErrPSKMismatch) {
		t.Errorf("an alert was raised but not classified as a PSK mismatch: %v", err)
	}
	t.Logf("mismatch reported as: %v", err)
}

// TestBridgeDecryptsApplicationData rehearses Phase 5c: the device sends an
// image as TLS application data and the bridge hands back the plaintext, which
// the 12-bit decoder then turns into 80 x 64 samples.
//
// The "image" is synthetic. What is real is the record framing, the encryption
// and the length: 5120 samples packed four per six bytes is 7680 bytes, and the
// decoder must accept exactly what comes back out.
func TestBridgeDecryptsApplicationData(t *testing.T) {
	psk := testPSK(0x3c)
	r := newRig(t, psk, psk)
	r.requestTLS(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.bridge.Handshake(ctx); err != nil {
		t.Fatalf("Handshake: %v\nlog:\n%s", err, r.log)
	}

	const (
		width, height = 80, 64
		want          = width * height / image.SamplesPer12BitGroup * image.BytesPer12BitGroup // 7680
	)
	frame := make([]byte, want)
	for i := range frame {
		frame[i] = byte(i*7 + 3)
	}
	if err := r.ec.SendPlaintext(frame); err != nil {
		t.Fatalf("the stand-in could not send the frame: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer readCancel()
	got, err := r.bridge.ReadApplicationData(readCtx, 500*time.Millisecond, 2*want)
	if err != nil {
		t.Fatalf("ReadApplicationData: %v\nlog:\n%s", err, r.log)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("plaintext round trip failed: got %d bytes, sent %d", len(got), len(frame))
	}

	samples, err := image.Decode12BitRaw(got, width, height)
	if err != nil {
		t.Fatalf("decoding the round-tripped frame: %v", err)
	}
	if len(samples) != width*height {
		t.Errorf("decoded %d samples, want %d", len(samples), width*height)
	}

	// Secret hygiene: a decrypted frame is what a fingerprint image looks like,
	// and the bridge logs record types and lengths only.
	if logged := r.log.String(); strings.Contains(logged, hex.EncodeToString(frame[:32])) {
		t.Errorf("the frame was written to the log:\n%s", logged)
	}
}

// TestRehearsalRefusesWhatALiveRunRefuses is the reason LoopbackEC implements
// transport.Peer instead of being handed to the bridge directly. A rehearsal that
// could send frames the live path refuses would be worse than no rehearsal.
func TestRehearsalRefusesWhatALiveRunRefuses(t *testing.T) {
	psk := testPSK(0x77)
	r := newRig(t, psk, psk)

	// The frame that wedged the EC: 0xe4 with no payload.
	if err := r.tr.Send(0xe4, nil); !errors.Is(err, transport.ErrRefused) {
		t.Errorf("Send(0xe4, nil) against the rehearsal = %v, want a refusal", err)
	}
	// A state-changing opcode the run did not unlock. Only 0xd0 is allowed here,
	// so a rehearsal cannot quietly send the rest of the init either.
	if err := r.tr.Send(0x90, make([]byte, 224)); !errors.Is(err, transport.ErrRefused) {
		t.Errorf("Send(0x90) against the rehearsal = %v, want a refusal", err)
	}
	if cmds := r.ec.Commands(); len(cmds) != 0 {
		t.Errorf("refused commands still reached the stand-in: %v", cmds)
	}
}

// TestDeliverLeavesCommandMessagesAlone: the bridge owns TLS packs only. An ACK
// or an unsolicited finger-detect event is the caller's business, and mistaking
// one for TLS data would corrupt the session.
func TestDeliverLeavesCommandMessagesAlone(t *testing.T) {
	b := &Bridge{opts: Options{}.withDefaults()}

	for _, raw := range [][]byte{
		proto.Encode(0xa8, []byte{0x00, 0x00}),         // a command frame
		proto.Encode(proto.AckCmd, []byte{0xa8, 0x01}), // an ACK
		{0x01, 0x02, 0x03},                             // not a pack at all
		proto.Encode(0x32, make([]byte, 16)),           // an FDT event
	} {
		forwarded, err := b.Deliver(raw)
		if err != nil {
			t.Errorf("Deliver(% x) = %v, want no error", raw[:min(len(raw), 4)], err)
		}
		if forwarded {
			t.Errorf("Deliver(% x) claimed a non-TLS transfer as its own", raw[:min(len(raw), 4)])
		}
	}
}

// TestAlertClassification pins the mapping from alert description to error,
// because that mapping is what a Phase 5b run will be read through.
func TestAlertClassification(t *testing.T) {
	b := &Bridge{opts: Options{}.withDefaults()}

	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"bad_record_mac", []byte{2, alertBadRecordMAC}, ErrPSKMismatch},
		{"decrypt_error", []byte{2, alertDecryptError}, ErrPSKMismatch},
		{"handshake_failure", []byte{2, alertHandshakeFailure}, ErrPSKMismatch},
		{"unknown_psk_identity", []byte{2, alertUnknownPSKID}, ErrPSKMismatch},
		{"protocol_version", []byte{2, alertProtocolVersion}, ErrAlert},
		{"close_notify", []byte{1, alertCloseNotify}, ErrAlert},
		{"encrypted, unreadable", make([]byte, 48), ErrAlert},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := b.alertError("the device", tc.body)
			if !errors.Is(err, tc.want) {
				t.Fatalf("alertError = %v, want it to wrap %v", err, tc.want)
			}
			// A non-mismatch alert must not be reported as one: Phase 5b turns
			// on telling "wrong key" apart from "something else went wrong".
			if tc.want == ErrAlert && errors.Is(err, ErrPSKMismatch) {
				t.Errorf("alertError = %v, wrongly classified as a PSK mismatch", err)
			}
		})
	}
}
