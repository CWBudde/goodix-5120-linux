package evtx

import (
	"encoding/binary"
	"sort"
	"strings"
	"time"
)

// Record header layout. Every EVTX record begins with this and ends with its
// own size repeated:
//
//	0x00  uint32  magic 0x00002a2a ("**\0\0")
//	0x04  uint32  size, counting this header and the trailing copy
//	0x08  uint64  record id
//	0x10  uint64  FILETIME
//	0x18  ...     binary XML
//	size-4 uint32 size again
//
// The repeated size is the validation. Scanning for the magic alone matches
// arbitrary payload bytes several times in a 20 MB log — the driver logs hex
// dumps, and "2a 2a 00 00" turns up inside them — and requiring the trailing
// copy to agree is what separates a record from a coincidence.
const (
	recordMagic     = 0x00002a2a
	recordHeaderLen = 0x18
	// minRecordLen is the smallest plausible record: the header, the trailing
	// size, and something between them.
	minRecordLen = 0x30
	// maxRecordLen is one chunk, because a record never straddles a chunk.
	maxRecordLen = ChunkSize
	// recordAlign is the alignment records are written at inside a chunk.
	// Chunks are themselves 64 KiB-aligned, so scanning the whole file at this
	// step reaches every record without parsing chunk headers.
	recordAlign = 8
)

// filetimeToUnix is the offset between the FILETIME epoch (1601-01-01 UTC) and
// the Unix epoch, in seconds. FILETIME counts 100 ns ticks.
const filetimeToUnix = 11644473600

// plausibleYear brackets the timestamps this package will believe. A record
// that passes the magic and the size check but claims to have been written in
// 1601 or 2184 is a false positive inside a hex dump, not a record.
const (
	minYear = 2000
	maxYear = 2100
)

// FileTime converts a Windows FILETIME to a Go time in UTC.
func FileTime(ft uint64) time.Time {
	return time.Unix(int64(ft/1e7)-filetimeToUnix, int64(ft%1e7)*100).UTC()
}

// Record is one recovered EVTX record.
//
// Strings holds the substitution values, in the order they appear in the
// record, already stripped of their length prefix (see strings.go) and already
// redacted (see redact.go). It is not the rendered message: the template text
// around these values is not reconstructed.
type Record struct {
	ID      uint64
	Time    time.Time
	Offset  int
	Strings []string
	// Redacted is set when at least one hex dump in this record was withheld.
	// Counting these is how a summary can say "18 records hold a payload this
	// tool will not print" without printing one.
	Redacted bool
}

// Text joins the recovered values. It is what a caller prints.
func (r Record) Text() string { return strings.Join(r.Strings, " | ") }

// Message returns the last recovered value, which for this driver's log is the
// one carrying the actual message; the values before it are the provider name
// and channel. Returning the last value rather than all of them is what makes
// two records with the same message group together.
func (r Record) Message() string {
	if len(r.Strings) == 0 {
		return ""
	}
	return strings.TrimSpace(r.Strings[len(r.Strings)-1])
}

// InRange reports whether the record falls inside [lo, hi]. Both bounds are
// inclusive, and a zero bound means unbounded on that side.
func (r Record) InRange(lo, hi time.Time) bool {
	if !lo.IsZero() && r.Time.Before(lo) {
		return false
	}
	if !hi.IsZero() && r.Time.After(hi) {
		return false
	}
	return true
}

// Scan recovers every record in a whole EVTX file, oldest first.
//
// The result is sorted rather than left in file order. A wrapped log's oldest
// chunk is not chunk 0, so file order is not time order, and reporting "the
// first record in the file" as the start of the log is exactly the mistake the
// 2026-09-20 recount had to undo. Ties on the timestamp — the log writes
// milliseconds and bursts of records share one — are broken by record id,
// which is assigned in write order.
//
// Bytes that look like a record but fail the trailing-size check, the length
// bounds or the plausible-year bracket are skipped silently. They are hex-dump
// coincidences, not truncated records, and there is nothing to report about
// them.
func Scan(b []byte) []Record {
	var out []Record
	for i := 0; i+minRecordLen <= len(b); i += recordAlign {
		if binary.LittleEndian.Uint32(b[i:]) != recordMagic {
			continue
		}
		size := int(binary.LittleEndian.Uint32(b[i+4:]))
		if size < minRecordLen || size > maxRecordLen || i+size > len(b) {
			continue
		}
		if int(binary.LittleEndian.Uint32(b[i+size-4:])) != size {
			continue
		}

		r := Record{
			ID:     binary.LittleEndian.Uint64(b[i+8:]),
			Time:   FileTime(binary.LittleEndian.Uint64(b[i+16:])),
			Offset: i,
		}
		if y := r.Time.Year(); y < minYear || y > maxYear {
			continue
		}

		// The body runs from the end of the header to the trailing size.
		for _, s := range values(b[i+recordHeaderLen : i+size-4]) {
			clean, hidden := Redact(s)
			r.Strings = append(r.Strings, clean)
			r.Redacted = r.Redacted || hidden
		}
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.Before(out[j].Time)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
