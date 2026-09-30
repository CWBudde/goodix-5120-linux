package proto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The two record headers below are the only ones this project has actually
// observed, both recorded in docs/protocol.md:
//
//   - 16 03 03 00 2f — the EC's ClientHello, from the vendor driver's ETW log
//     (the 23:25:41 handshake), 47 body bytes offering only 0x00ae.
//   - 17 03 03 1e 40 — an image, from dump.pcapng: application data with a
//     7744-byte body, arriving as a single b0 pack.
//
// Testing against them rather than against invented headers is the point: if
// ParseTLSRecordHeader cannot read the two records the device really sends, the
// bridge cannot work.
var (
	observedClientHelloHeader = []byte{0x16, 0x03, 0x03, 0x00, 0x2f}
	observedImageHeader       = []byte{0x17, 0x03, 0x03, 0x1e, 0x40}
)

func TestParseTLSRecordHeaderObserved(t *testing.T) {
	cases := []struct {
		name    string
		header  []byte
		typ     byte
		bodyLen int
	}{
		{"EC ClientHello (vendor log)", observedClientHelloHeader, TLSHandshake, 0x2f},
		{"image record (dump.pcapng)", observedImageHeader, TLSApplicationData, 7744},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			typ, major, minor, bodyLen, err := ParseTLSRecordHeader(tc.header)
			if err != nil {
				t.Fatalf("ParseTLSRecordHeader(% x) = %v", tc.header, err)
			}
			if typ != tc.typ {
				t.Errorf("type = 0x%02x, want 0x%02x", typ, tc.typ)
			}
			if major != 0x03 || minor != 0x03 {
				t.Errorf("version = %d.%d, want 3.3 (TLS 1.2)", major, minor)
			}
			if bodyLen != tc.bodyLen {
				t.Errorf("body length = %d, want %d", bodyLen, tc.bodyLen)
			}
		})
	}
}

// TestParseTLSRecordHeaderTellsShortFromMalformed pins the distinction the
// bridge depends on: a caller reading from a stream must be able to tell "read
// more bytes" from "this stream is not TLS".
func TestParseTLSRecordHeaderTellsShortFromMalformed(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShortBuffer},
		{"one byte short of a header", observedImageHeader[:4], ErrShortBuffer},
		{"unknown content type", []byte{0x18, 0x03, 0x03, 0x00, 0x10}, ErrTLSRecord},
		{"a Goodix message mistaken for a record", []byte{0xa0, 0x06, 0x00, 0xa6, 0xb0}, ErrTLSRecord},
		{"SSL 2.0 style version", []byte{0x16, 0x02, 0x00, 0x00, 0x10}, ErrTLSRecord},
		{"zero-length body", []byte{0x17, 0x03, 0x03, 0x00, 0x00}, ErrTLSRecord},
		{"body over the TLS limit", []byte{0x17, 0x03, 0x03, 0xff, 0xff}, ErrTLSRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := ParseTLSRecordHeader(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseTLSRecordHeader(% x) = %v, want an error wrapping %v", tc.in, err, tc.want)
			}
		})
	}
}

// TestParseTLSRecordHeaderIgnoresTheBody checks that a header can be parsed on
// its own, which is what lets the bridge read five bytes, learn the length, and
// then read exactly the body.
func TestParseTLSRecordHeaderIgnoresTheBody(t *testing.T) {
	_, _, _, bodyLen, err := ParseTLSRecordHeader(observedImageHeader)
	if err != nil {
		t.Fatalf("parsing a bare header: %v", err)
	}
	if bodyLen != 7744 {
		t.Fatalf("body length = %d, want 7744", bodyLen)
	}
}

func TestSplitTLSRecords(t *testing.T) {
	// A server's second handshake flight: change cipher spec, then Finished.
	// Two records in one buffer is exactly the case the bridge must split
	// before handing anything to the device.
	ccs := append(append([]byte{}, TLSChangeCipherSpec, 0x03, 0x03, 0x00, 0x01), 0x01)
	fin := append(append([]byte{}, TLSHandshake, 0x03, 0x03, 0x00, 0x04), 0xde, 0xad, 0xbe, 0xef)

	recs, err := SplitTLSRecords(append(append([]byte{}, ccs...), fin...))
	if err != nil {
		t.Fatalf("SplitTLSRecords: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Type != TLSChangeCipherSpec || !bytes.Equal(recs[0].Body, []byte{0x01}) {
		t.Errorf("record 0 = %v body % x", recs[0], recs[0].Body)
	}
	if recs[1].Type != TLSHandshake || !bytes.Equal(recs[1].Body, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("record 1 = %v body % x", recs[1], recs[1].Body)
	}
	if got, want := recs[0].Len()+recs[1].Len(), len(ccs)+len(fin); got != want {
		t.Errorf("record lengths sum to %d, want %d", got, want)
	}
}

// TestSplitTLSRecordsRefusesAPartialRecord is the property the transport gate
// relies on. Half a record on the wire is a frame no working driver produces,
// and this project has one hard-won rule about frames like that.
func TestSplitTLSRecordsRefusesAPartialRecord(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty buffer", nil},
		{"header only, body missing", observedImageHeader},
		{"body one byte short", append(append([]byte{}, TLSHandshake, 0x03, 0x03, 0x00, 0x04), 0x01, 0x02, 0x03)},
		{"trailing junk after a whole record",
			append(append([]byte{}, TLSHandshake, 0x03, 0x03, 0x00, 0x01, 0x01), 0xff)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SplitTLSRecords(tc.in); err == nil {
				t.Fatalf("SplitTLSRecords(% x) was accepted", tc.in)
			}
		})
	}
}

// TestTLSRecordStringHidesTheBody: a record body on this device is a
// fingerprint image, so no log line may contain one.
func TestTLSRecordStringHidesTheBody(t *testing.T) {
	secret := []byte{0xde, 0xad, 0xbe, 0xef}
	r := TLSRecord{Type: TLSApplicationData, Major: 3, Minor: 3, Body: secret}
	got := r.String()
	if bytes.Contains([]byte(got), secret) {
		t.Fatalf("TLSRecord.String() leaked the body: %q", got)
	}
	if want := "application data, TLS 1.2, 4-byte body"; got != want {
		t.Errorf("TLSRecord.String() = %q, want %q", got, want)
	}
}

func TestDescribeTLSRecord(t *testing.T) {
	if got := DescribeTLSRecord(observedImageHeader); got != "application data, TLS 1.2, 7744-byte record" {
		t.Errorf("DescribeTLSRecord = %q", got)
	}
	if got := DescribeTLSRecord(observedImageHeader[:3]); got != "" {
		t.Errorf("DescribeTLSRecord of a stub = %q, want \"\"", got)
	}
}

// TestPlaintextHexNeverPrintsAnImage is the important half of the rule: an
// application-data record is a fingerprint on this device, and no amount of
// logging convenience may print one. The rule is by record type, so this holds
// for every length and at every point in the session.
func TestPlaintextHexNeverPrintsAnImage(t *testing.T) {
	// The real thing: the record length seen from the device in dump.pcapng.
	body := make([]byte, 7744)
	for i := range body {
		body[i] = byte(i)
	}
	rec := append([]byte{TLSApplicationData, 0x03, 0x03, 0x1e, 0x40}, body...)

	if got := TLSPlaintextHex(rec); got != "" {
		t.Errorf("TLSPlaintextHex printed %d characters of an image record", len(got))
	}
	if got := (TLSRecord{Type: TLSApplicationData, Body: body}).PlaintextHex(); got != "" {
		t.Errorf("TLSRecord.PlaintextHex printed %d characters of an image record", len(got))
	}
}

// TestPlaintextHexPrintsHandshakeRecords pins the other half. The bytes are the
// EC's own ClientHello from Run 11 — a public handshake value, and the only
// reason that stalled handshake could be reproduced offline.
func TestPlaintextHexPrintsHandshakeRecords(t *testing.T) {
	rec := []byte{TLSHandshake, 0x03, 0x03, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0x03, 0x03}
	want := "010000020303"
	if got := TLSPlaintextHex(rec); got != want {
		t.Errorf("TLSPlaintextHex = %q, want %q", got, want)
	}
	for _, typ := range []byte{TLSChangeCipherSpec, TLSAlert} {
		r := TLSRecord{Type: typ, Body: []byte{0x02, 0x14}}
		if got := r.PlaintextHex(); got != "0214" {
			t.Errorf("PlaintextHex for type 0x%02x = %q, want %q", typ, got, "0214")
		}
	}
}

// TestPlaintextHexTruncates keeps one very long handshake record from filling a
// bisect log, without letting it look complete.
func TestPlaintextHexTruncates(t *testing.T) {
	body := make([]byte, MaxLoggedRecord+9)
	got := (TLSRecord{Type: TLSHandshake, Body: body}).PlaintextHex()
	if !strings.Contains(got, "(9 more byte(s))") {
		t.Errorf("PlaintextHex of a %d-byte body did not say what it left out: %q", len(body), got)
	}
	if len(got) > 2*MaxLoggedRecord+32 {
		t.Errorf("PlaintextHex returned %d characters for a %d-byte body", len(got), len(body))
	}
}

// Accept only TLS 1.0 through 1.2 record versions, including older ClientHello framing.
func TestParseTLSRecordHeaderVersionRange(t *testing.T) {
	for _, minor := range []byte{0, 1, 2, 3, 4, 255} {
		header := []byte{TLSHandshake, 3, minor, 0, 1}
		_, _, _, _, err := ParseTLSRecordHeader(header)
		if minor >= 1 && minor <= 3 {
			if err != nil {
				t.Errorf("minor %d: %v", minor, err)
			}
		} else if !errors.Is(err, ErrTLSRecord) {
			t.Errorf("minor %d accepted: %v", minor, err)
		}
	}
}
