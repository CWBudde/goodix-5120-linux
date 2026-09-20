// Command goodix-evtx reads the Goodix driver's Windows debug log offline.
//
// The log is the ETW channel `Goodix-FingerprintProvider/Debug`, which the
// vendor's gfusb.inf enables and which the driver fills with every frame it
// sends and receives. It is the source of the init sequence in
// docs/protocol.md, and of the record counts, dates and init tallies that file
// records. This command exists so those numbers can be re-derived rather than
// remembered.
//
// It opens no device and writes no file: input is a path, output is stdout.
// The repository's safety argument rests on cmd/goodix-probe being the only
// thing that can reach the embedded controller, and a log reader has no
// business being able to. A test parses this directory's imports to keep it so.
//
// The default mode prints a summary and no record text. The log is not
// biometric, but it holds the device OTP, a hash of the device PSK, the frames
// of every init and strings naming the machine and the driver build; printing
// 17545 records because someone asked for a count is not a reasonable default.
// The OTP and the PSK hash are withheld outright, by internal/evtx, and no
// flag here can ask for them.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"goodix5120/internal/evtx"
)

// timeLayout is the -from/-to format. Local time, because the question asked of
// this log is always "what happened when I did that", and the person who did it
// was not thinking in UTC.
const timeLayout = "2006-01-02 15:04:05"

func main() {
	var (
		in     = flag.String("in", "", "evtx file to read (required)")
		text   = flag.Bool("text", false, "print record text, bounded by -n; off by default")
		grep   = flag.String("grep", "", "print only records containing this substring (case-insensitive); implies -text")
		limit  = flag.Int("n", 50, "stop after this many printed records (0 = no limit)")
		from   = flag.String("from", "", "ignore records before this local time ("+timeLayout+")")
		to     = flag.String("to", "", "ignore records after this local time")
		hours  = flag.Bool("hours", false, "also print the per-hour record histogram")
		shapes = flag.Int("shapes", 20, "how many message shapes to list in the summary")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)
	if *in == "" {
		logger.Print("usage: goodix-evtx -in log.evtx [-hours] [-grep substring] [-text -n 50]")
		os.Exit(2)
	}

	if err := run(logger, options{
		path: *in, text: *text, grep: *grep, limit: *limit,
		from: *from, to: *to, hours: *hours, shapes: *shapes,
	}); err != nil {
		logger.Printf("goodix-evtx: %v", err)
		os.Exit(1)
	}
}

type options struct {
	path   string
	text   bool
	grep   string
	limit  int
	from   string
	to     string
	hours  bool
	shapes int
}

func run(logger *log.Logger, o options) error {
	lo, err := parseTime(o.from)
	if err != nil {
		return err
	}
	hi, err := parseTime(o.to)
	if err != nil {
		return err
	}

	b, err := os.ReadFile(o.path)
	if err != nil {
		return err
	}

	// The header is parsed for its own sake: it is the only thing in the file
	// that says whether the log has wrapped, and a date range from a wrapped log
	// means something different from one from a log that has not.
	head, err := evtx.ParseHeader(b)
	if err != nil {
		return err
	}

	all := evtx.Scan(b)
	if len(all) == 0 {
		return fmt.Errorf("no EVTX records found in %s", o.path)
	}

	recs := make([]evtx.Record, 0, len(all))
	for _, r := range all {
		if r.InRange(lo, hi) {
			recs = append(recs, r)
		}
	}
	if len(recs) == 0 {
		return fmt.Errorf("%d records found, none of them between %s and %s", len(all), o.from, o.to)
	}

	printHeader(logger, head)
	printSummary(logger, evtx.Summarise(recs), len(all), len(recs), o)

	if o.text || o.grep != "" {
		printRecords(logger, recs, o)
	} else {
		logger.Print("\nRecord text is not printed. Pass -grep to filter for it, or -text for all of it.")
	}
	return nil
}

func printHeader(logger *log.Logger, h evtx.Header) {
	logger.Printf("EVTX %d.%d, %d chunks of %d KiB, first chunk %d, last chunk %d, next record id %d",
		h.Major, h.Minor, h.Chunks, evtx.ChunkSize>>10, h.FirstChunk, h.LastChunk, h.NextRecordID)
	if h.Wrapped() {
		logger.Print("the circular buffer has wrapped: anything older than the span below was overwritten,")
		logger.Print("so the first timestamp is when the log wrapped past, not when logging began")
	}
}

func printSummary(logger *log.Logger, s evtx.Summary, total, kept int, o options) {
	if kept != total {
		logger.Printf("\n%d records in the file, %d in the requested time range", total, kept)
	} else {
		logger.Printf("\n%d records", total)
	}
	logger.Printf("record ids %d..%d", s.FirstID, s.LastID)
	logger.Printf("%s .. %s (local), spanning %s",
		stamp(s.First), stamp(s.Last), span(s.Last.Sub(s.First)))
	if s.Redacted > 0 {
		logger.Printf("%d records hold a hex dump this tool withholds; its length is still reported", s.Redacted)
	}

	logger.Printf("\ntop %d message shapes (numbers and hex collapsed; no record text):", o.shapes)
	for _, sc := range s.TopShapes(o.shapes) {
		logger.Printf("  %6d  %s", sc.Count, sc.Shape)
	}
	if n := len(s.Shapes); n > o.shapes {
		logger.Printf("  ... and %d more shapes", n-o.shapes)
	}

	if o.hours {
		logger.Print("\nrecords per hour:")
		for _, k := range s.Hours() {
			logger.Printf("  %s  %6d", k, s.PerHour[k])
		}
	}
}

func printRecords(logger *log.Logger, recs []evtx.Record, o options) {
	want := strings.ToLower(o.grep)
	logger.Print("")

	n, matched := 0, 0
	for _, r := range recs {
		t := r.Text()
		if want != "" && !strings.Contains(strings.ToLower(t), want) {
			continue
		}
		matched++
		if o.limit > 0 && n >= o.limit {
			continue
		}
		logger.Printf("%s  #%d  %s", r.Time.Local().Format("2006-01-02 15:04:05.000"), r.ID, t)
		n++
	}

	logger.Printf("\n%d records matched, %d printed", matched, n)
	if o.limit > 0 && matched > n {
		logger.Printf("raise -n past %d to see the rest", o.limit)
	}
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.ParseInLocation(timeLayout, s, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad time %q, want %q: %w", s, timeLayout, err)
	}
	return t, nil
}

// stamp names the zone. The FILETIMEs in the file are UTC; printing them that
// way against a log written in CEST silently shifts every event by two hours.
func stamp(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05.000 MST") }

// span prints a duration in days and hours, because this log covers five weeks
// and Go's own formatting would render that as 851h13m.
func span(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days == 0 {
		return fmt.Sprintf("%dh%dm", hours, int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", days, hours)
}
