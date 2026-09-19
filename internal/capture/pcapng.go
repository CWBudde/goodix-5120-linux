// Package capture reads USB captures offline.
//
// It exists so that a fixture built from a vendor capture is produced by
// reviewable code rather than by a human promising what they scrubbed. The
// captures themselves are gitignored and irreplaceable without another Windows
// session, so the reduction of them has to be reproducible.
//
// This package reads files. It cannot reach a device: it imports only the
// standard library and internal/proto, which is itself stdlib-only, and
// purity_test.go asserts that. A tool that can only read a file cannot wedge
// the embedded controller, and that must be a property of the code rather than
// of anyone's intent.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// pcapng block types, from the pcapng specification.
const (
	blockSectionHeader         = 0x0a0d0d0a
	blockInterfaceDesc         = 0x00000001
	blockEnhancedPacket        = 0x00000006
	byteOrderMagic      uint32 = 0x1a2b3c4d
)

// LinkTypeUSBPcap is the pcapng link type written by USBPcap on Windows.
const LinkTypeUSBPcap = 249

// ErrFormat means the file is not a pcapng file this package can read.
var ErrFormat = errors.New("capture: malformed or unsupported pcapng")

// Block is one pcapng block, with its body still encoded.
type Block struct {
	Type uint32
	Body []byte
	// ByteOrder is the section's byte order, needed to decode Body.
	ByteOrder binary.ByteOrder
}

// maxBlockLen caps a single block at 16 MiB. A USB capture block is a few
// kilobytes; anything larger means a corrupt length field, and refusing it
// keeps a malformed file from being turned into an allocation.
const maxBlockLen = 16 << 20

// Reader walks the blocks of a pcapng file. It holds one block at a time, so a
// half-megabyte capture and a half-gigabyte one cost the same.
type Reader struct {
	r     io.Reader
	order binary.ByteOrder
	// linkTypes records each interface's link type, in description order.
	linkTypes []uint16
	err       error
}

// NewReader starts reading a pcapng stream.
func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// LinkTypes returns the link type of every interface described so far.
func (rd *Reader) LinkTypes() []uint16 { return rd.linkTypes }

// Next returns the next block, or io.EOF at the end of the stream.
func (rd *Reader) Next() (Block, error) {
	if rd.err != nil {
		return Block{}, rd.err
	}

	var head [8]byte
	if _, err := io.ReadFull(rd.r, head[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = fmt.Errorf("%w: truncated block header", ErrFormat)
		}
		rd.err = err
		return Block{}, err
	}

	typ := binary.LittleEndian.Uint32(head[0:4])
	if typ == blockSectionHeader {
		// A section header names the byte order for everything after it, so it
		// has to be parsed before its own length field can be trusted.
		return rd.readSectionHeader(head)
	}
	if rd.order == nil {
		rd.err = fmt.Errorf("%w: first block is 0x%08x, not a section header", ErrFormat, typ)
		return Block{}, rd.err
	}

	typ = rd.order.Uint32(head[0:4])
	total := rd.order.Uint32(head[4:8])
	body, err := rd.readBody(total)
	if err != nil {
		return Block{}, err
	}

	if typ == blockInterfaceDesc && len(body) >= 2 {
		rd.linkTypes = append(rd.linkTypes, rd.order.Uint16(body[0:2]))
	}
	return Block{Type: typ, Body: body, ByteOrder: rd.order}, nil
}

func (rd *Reader) readSectionHeader(head [8]byte) (Block, error) {
	// Read the byte-order magic before committing to an interpretation of the
	// length field, which is in the section's own order.
	var magic [4]byte
	if _, err := io.ReadFull(rd.r, magic[:]); err != nil {
		rd.err = fmt.Errorf("%w: truncated section header", ErrFormat)
		return Block{}, rd.err
	}

	switch {
	case binary.LittleEndian.Uint32(magic[:]) == byteOrderMagic:
		rd.order = binary.LittleEndian
	case binary.BigEndian.Uint32(magic[:]) == byteOrderMagic:
		rd.order = binary.BigEndian
	default:
		rd.err = fmt.Errorf("%w: bad byte-order magic %x", ErrFormat, magic)
		return Block{}, rd.err
	}

	total := rd.order.Uint32(head[4:8])
	if total < 16 {
		rd.err = fmt.Errorf("%w: section header length %d", ErrFormat, total)
		return Block{}, rd.err
	}
	// The magic is already consumed, so the remaining body is 4 bytes shorter.
	body, err := rd.readBodyFrom(total, 4, magic[:])
	if err != nil {
		return Block{}, err
	}
	// A new section resets the interface table.
	rd.linkTypes = nil
	return Block{Type: blockSectionHeader, Body: body, ByteOrder: rd.order}, nil
}

// readBody reads a block body given the block's total length, and checks the
// trailing length field that pcapng repeats at the end of every block.
func (rd *Reader) readBody(total uint32) ([]byte, error) {
	return rd.readBodyFrom(total, 0, nil)
}

func (rd *Reader) readBodyFrom(total uint32, already int, prefix []byte) ([]byte, error) {
	if total < 12 || total > maxBlockLen || total%4 != 0 {
		rd.err = fmt.Errorf("%w: implausible block length %d", ErrFormat, total)
		return nil, rd.err
	}

	// total counts the 8-byte header and the 4-byte trailing length.
	rest := int(total) - 12 - already
	if rest < 0 {
		rd.err = fmt.Errorf("%w: block length %d too small", ErrFormat, total)
		return nil, rd.err
	}

	body := make([]byte, len(prefix)+rest)
	copy(body, prefix)
	if _, err := io.ReadFull(rd.r, body[len(prefix):]); err != nil {
		rd.err = fmt.Errorf("%w: truncated block body", ErrFormat)
		return nil, rd.err
	}

	var tail [4]byte
	if _, err := io.ReadFull(rd.r, tail[:]); err != nil {
		rd.err = fmt.Errorf("%w: truncated block trailer", ErrFormat)
		return nil, rd.err
	}
	if got := rd.order.Uint32(tail[:]); got != total {
		rd.err = fmt.Errorf("%w: trailing length %d does not match %d", ErrFormat, got, total)
		return nil, rd.err
	}
	return body, nil
}
