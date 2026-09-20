package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The TLS record layer.
//
// After `0xd0` the EC opens a TLS 1.2 handshake as the CLIENT, and every record
// in both directions travels as the payload of a `0xb0` pack (docs/protocol.md,
// "TLS"). Two callers therefore need to know where one record ends and the next
// begins: the transport's safety gate, which refuses to put a truncated record
// on the wire, and the session bridge, which forwards records between the
// device and the local TLS endpoint.
//
// Finding record boundaries is pure byte work with no I/O, which is why it
// lives here. Nothing in this file decrypts, authenticates or interprets a
// record body — a body is an opaque slice, and on this device it is a
// fingerprint image.

const (
	// TLSRecordHeaderLen is the size of a record header:
	//
	//	[type:1][version major:1][version minor:1][body length:2 BE]
	//
	// Note the length is BIG endian, unlike every length in the Goodix framing
	// around it.
	TLSRecordHeaderLen = 5

	// MaxTLSRecordBody is TLS 1.2's own ceiling on one record body: 2^14 bytes
	// of plaintext plus up to 2048 bytes of cipher expansion (RFC 5246 §6.2.3).
	// The largest body observed from this device is 7744, an image.
	MaxTLSRecordBody = 1<<14 + 2048
)

// TLS record content types (RFC 5246 §6.2.1). Only these four exist; a fifth
// value is a framing error rather than a record this code does not know.
const (
	TLSChangeCipherSpec byte = 0x14
	TLSAlert            byte = 0x15
	TLSHandshake        byte = 0x16
	TLSApplicationData  byte = 0x17
)

// tlsVersionMajor is the major version of every TLS version through 1.3.
const tlsVersionMajor = 0x03

// ErrTLSRecord means a buffer is not a well-formed TLS record. A record that is
// merely incomplete reports ErrShortBuffer instead, so a caller reading from a
// stream can tell "read more" from "this is not TLS".
var ErrTLSRecord = errors.New("proto: not a well-formed TLS record")

// TLSRecord is one record: its content type, its protocol version and its body.
type TLSRecord struct {
	// Type is one of the four content types above.
	Type byte
	// Major, Minor are the version bytes as they appear on the wire, so TLS 1.2
	// is {3, 3}.
	Major, Minor byte
	// Body is the record body. It ALIASES the buffer it was parsed from — no
	// copy is made, because a body here is up to 7744 bytes of image and every
	// caller either forwards it immediately or holds the buffer anyway. Copy it
	// if you need to outlive the buffer.
	Body []byte
}

// Len is the record's total size on the wire, header included.
func (r TLSRecord) Len() int { return TLSRecordHeaderLen + len(r.Body) }

// String renders the record for a log line. It never prints the body: on this
// device a body is a fingerprint image.
func (r TLSRecord) String() string {
	return fmt.Sprintf("%s, TLS 1.%d, %d-byte body", TLSTypeName(r.Type), int(r.Minor)-1, len(r.Body))
}

// TLSTypeName names a content type for a log line.
func TLSTypeName(t byte) string {
	switch t {
	case TLSChangeCipherSpec:
		return "change cipher spec"
	case TLSAlert:
		return "alert"
	case TLSHandshake:
		return "handshake"
	case TLSApplicationData:
		return "application data"
	default:
		return fmt.Sprintf("type 0x%02x", t)
	}
}

// ParseTLSRecordHeader validates the five header bytes at the start of b and
// returns the record's type, version and body length. b may be exactly the
// header: nothing beyond it is read, which is what lets a caller read a header
// from a stream, then read exactly bodyLen bytes more.
//
// A buffer shorter than a header reports ErrShortBuffer. Anything else wrong —
// an unknown content type, a non-TLS version, an over-long body — reports
// ErrTLSRecord.
func ParseTLSRecordHeader(b []byte) (typ, major, minor byte, bodyLen int, err error) {
	if len(b) < TLSRecordHeaderLen {
		return 0, 0, 0, 0, fmt.Errorf("%w: TLS record header needs %d bytes, got %d",
			ErrShortBuffer, TLSRecordHeaderLen, len(b))
	}

	typ, major, minor = b[0], b[1], b[2]
	switch typ {
	case TLSChangeCipherSpec, TLSAlert, TLSHandshake, TLSApplicationData:
	default:
		return 0, 0, 0, 0, fmt.Errorf("%w: content type 0x%02x is not one of 0x14, 0x15, 0x16, 0x17", ErrTLSRecord, typ)
	}
	if major != tlsVersionMajor {
		return 0, 0, 0, 0, fmt.Errorf("%w: version major byte is 0x%02x, want 0x%02x", ErrTLSRecord, major, tlsVersionMajor)
	}

	bodyLen = int(binary.BigEndian.Uint16(b[3:5]))
	if bodyLen == 0 {
		// An empty record is legal in TLS but has never been seen here, and a
		// zero length is the shape a truncated or mis-framed buffer takes.
		return 0, 0, 0, 0, fmt.Errorf("%w: record declares a zero-length body", ErrTLSRecord)
	}
	if bodyLen > MaxTLSRecordBody {
		return 0, 0, 0, 0, fmt.Errorf("%w: record declares %d body bytes, over the TLS limit of %d",
			ErrTLSRecord, bodyLen, MaxTLSRecordBody)
	}
	return typ, major, minor, bodyLen, nil
}

// SplitTLSRecords splits a buffer into the whole records it holds. Every byte
// must belong to a complete record: a trailing partial record is an error, not
// a remainder, because the one caller that splits a complete buffer — the
// transport gate — must never hand the EC half a record.
//
// Use ParseTLSRecordHeader directly when reading from a stream, where a partial
// record just means "read more".
func SplitTLSRecords(b []byte) ([]TLSRecord, error) {
	var out []TLSRecord
	for off := 0; off < len(b); {
		typ, major, minor, bodyLen, err := ParseTLSRecordHeader(b[off:])
		if err != nil {
			return nil, fmt.Errorf("record %d at offset %d: %w", len(out), off, err)
		}
		end := off + TLSRecordHeaderLen + bodyLen
		if end > len(b) {
			return nil, fmt.Errorf("%w: record %d at offset %d declares %d body bytes but only %d remain",
				ErrTLSRecord, len(out), off, bodyLen, len(b)-off-TLSRecordHeaderLen)
		}
		out = append(out, TLSRecord{
			Type:  typ,
			Major: major,
			Minor: minor,
			Body:  b[off+TLSRecordHeaderLen : end],
		})
		off = end
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: buffer is empty", ErrTLSRecord)
	}
	return out, nil
}

// DescribeTLSRecord summarises the record at the start of b for a log line, or
// returns "" if b is too short to hold a header. It is deliberately tolerant:
// it describes what the header says even when the header is malformed, because
// the point of the line is to show what arrived.
func DescribeTLSRecord(b []byte) string {
	if len(b) < TLSRecordHeaderLen {
		return ""
	}
	return fmt.Sprintf("%s, TLS 1.%d, %d-byte record", TLSTypeName(b[0]), int(b[2])-1,
		binary.BigEndian.Uint16(b[3:5]))
}
