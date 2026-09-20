// Package evtx reads a Windows EVTX event log offline.
//
// It exists because every correction made to docs/protocol.md on 2026-09-20 —
// the record count, the dates the log really covers, how many inits it holds
// and how many of those are complete — came out of a throwaway scanner that
// lived in nobody's repository. A finding that cannot be re-derived from code
// is a finding that has to be taken on trust, and the earlier reading it
// replaced ("2026-08-11 to 2026-09-19, 8 complete inits", from `strings -el`)
// is what taking that on trust costs.
//
// # This is not a binary-XML parser
//
// EVTX stores each event as binary XML: a template holding the static text,
// plus an array of substitution values that fill its placeholders. A real
// parser resolves the template and reassembles the sentence. This package does
// not. It recovers the substitution values only, which are stored as plain
// UTF-16LE, and never reconstructs the template-owned static text.
//
// That is enough for the question this repository asks — "what was logged, and
// when" — because the Goodix driver puts the whole interesting part of each
// message into one substitution value. It is not enough for anything that
// depends on the surrounding sentence, an event ID, a level or a channel. Say
// so rather than letting a caller assume otherwise: a message this package
// reports is a fragment, and a message it does not report may still be in the
// file.
//
// # It reads a buffer
//
// This package imports the standard library and nothing else — not
// internal/proto, not internal/transport, certainly not gousb — and
// purity_test.go parses the source to keep it that way. It takes bytes and
// returns records. It opens no file, and it could not reach the embedded
// controller if it wanted to.
//
// # It withholds two payloads
//
// The driver's debug log is not biometric, but it logs the 0xa6 reply (the
// device OTP, also spelled out under several "OTP::0x" labels) and the 0xe4
// reply (a hash of the device PSK) in full hex. Those are the two payloads
// cmd/goodix-pcap already refuses to print. Here the refusal happens in Scan,
// before a Record exists, so no later print path can reopen it. See redact.go.
package evtx

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrFormat means the bytes are not an EVTX file this package can read.
var ErrFormat = errors.New("evtx: not an EVTX file")

// ChunkSize is the size of one EVTX chunk. Records live inside chunks and
// never straddle one, which is why no record can be larger than this.
const ChunkSize = 64 << 10

// File header layout, from the EVTX format. Only the fields this package can
// act on are named; the rest of the 4096-byte header block is skipped.
const (
	headerMagic   = "ElfFile\x00"
	offFirstChunk = 0x08 // uint64
	offLastChunk  = 0x10 // uint64
	offNextRecord = 0x18 // uint64
	offHeaderSize = 0x20 // uint32, 0x80 in every file observed
	offMinor      = 0x24 // uint16
	offMajor      = 0x26 // uint16
	offBlockSize  = 0x28 // uint16, 0x1000
	offChunkCount = 0x2a // uint16
	headerLen     = 0x80
)

// Header is what the EVTX file header says about the log as a whole.
//
// The chunk numbers are the reason to parse it at all. An EVTX log is a
// circular buffer of a fixed number of chunks, and the header names which chunk
// currently holds the oldest records and which holds the newest. Once the log
// has wrapped, FirstChunk is no longer 0, and everything older than the oldest
// surviving chunk is overwritten and gone — a fact that has to be reported
// alongside any date range, or the earliest timestamp in the file reads as the
// date logging began. It is not. It is the date the log last wrapped past.
type Header struct {
	FirstChunk   uint64
	LastChunk    uint64
	NextRecordID uint64
	Major, Minor uint16
	Chunks       uint16
}

// ParseHeader reads the file header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < headerLen {
		return Header{}, fmt.Errorf("%w: %d bytes is shorter than the file header", ErrFormat, len(b))
	}
	if string(b[:len(headerMagic)]) != headerMagic {
		return Header{}, fmt.Errorf("%w: header magic is %q, not %q", ErrFormat, b[:len(headerMagic)], headerMagic)
	}
	if got := binary.LittleEndian.Uint32(b[offHeaderSize:]); got != headerLen {
		return Header{}, fmt.Errorf("%w: header size %d, want %d", ErrFormat, got, headerLen)
	}

	h := Header{
		FirstChunk:   binary.LittleEndian.Uint64(b[offFirstChunk:]),
		LastChunk:    binary.LittleEndian.Uint64(b[offLastChunk:]),
		NextRecordID: binary.LittleEndian.Uint64(b[offNextRecord:]),
		Minor:        binary.LittleEndian.Uint16(b[offMinor:]),
		Major:        binary.LittleEndian.Uint16(b[offMajor:]),
		Chunks:       binary.LittleEndian.Uint16(b[offChunkCount:]),
	}
	if got := binary.LittleEndian.Uint16(b[offBlockSize:]); got != 0x1000 {
		return Header{}, fmt.Errorf("%w: header block size %d, want 4096", ErrFormat, got)
	}
	return h, nil
}

// Wrapped reports whether the circular chunk buffer has come round at least
// once, so that records older than the first surviving chunk are gone.
//
// Observed on Goodix-FingerprintProvider%4Debug.evtx: 320 chunks, first chunk
// 28, last chunk 27. The oldest chunk sits one past the newest, which is what a
// circular buffer looks like after it has filled. A log that has never wrapped
// starts at chunk 0.
func (h Header) Wrapped() bool { return h.FirstChunk > h.LastChunk }
