package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// internalKeyboardName is the evdev name of the i8042 keyboard the EC drives.
const internalKeyboardName = "AT Translated Set 2 keyboard"

// linuxHost observes the real machine. Everything it does is read-only apart
// from Mark, which appends to the kernel log.
type linuxHost struct {
	keys  chan struct{}
	done  chan error
	marks bool
	ec    *ecRefreshCounter
}

// newLinuxHost opens the internal keyboard for reading. It does not grab the
// device, so key presses still reach the desktop as usual.
func newLinuxHost(marks bool) (*linuxHost, error) {
	path, err := findKeyboard()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s (needs root or the input group): %w", path, err)
	}
	h := &linuxHost{
		keys:  make(chan struct{}, 64),
		done:  make(chan error, 1),
		marks: marks,
		ec:    &ecRefreshCounter{read: readBatteryTuple},
	}
	h.ec.sample() // establish a baseline before the first check
	go h.read(f)
	go h.ec.poll(time.Second)
	return h, nil
}

// findKeyboard returns the /dev/input node of the internal keyboard.
func findKeyboard() (string, error) {
	names, _ := filepath.Glob("/sys/class/input/event*/device/name")
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err == nil && strings.TrimSpace(string(b)) == internalKeyboardName {
			event := filepath.Base(filepath.Dir(filepath.Dir(n)))
			return "/dev/input/" + event, nil
		}
	}
	return "", fmt.Errorf("no input device named %q", internalKeyboardName)
}

// inputEventSize is sizeof(struct input_event): a struct timeval (two longs)
// followed by u16 type, u16 code and s32 value.
const inputEventSize = 2*strconv.IntSize/8 + 8

// read forwards every key-down event to h.keys until the device fails.
func (h *linuxHost) read(f *os.File) {
	defer f.Close()
	buf := make([]byte, inputEventSize)
	for {
		if _, err := io.ReadFull(f, buf); err != nil {
			h.done <- err
			return
		}
		tv := inputEventSize - 8
		typ := binary.NativeEndian.Uint16(buf[tv:])
		value := int32(binary.NativeEndian.Uint32(buf[tv+4:]))
		if typ == 1 && value == 1 { // EV_KEY, pressed
			select {
			case h.keys <- struct{}{}:
			default:
			}
		}
	}
}

func (h *linuxHost) WaitKey(timeout time.Duration) (bool, error) {
	// Discard presses made before the prompt, e.g. the Enter that started
	// the program.
drain:
	for {
		select {
		case <-h.keys:
		default:
			break drain
		}
	}
	select {
	case <-h.keys:
		return true, nil
	case err := <-h.done:
		return false, fmt.Errorf("reading the keyboard: %w", err)
	case <-time.After(timeout):
		return false, nil
	}
}

func (h *linuxHost) SensorPresent() bool {
	dirs, _ := filepath.Glob("/sys/bus/usb/devices/*")
	for _, d := range dirs {
		v, _ := os.ReadFile(filepath.Join(d, "idVendor"))
		p, _ := os.ReadFile(filepath.Join(d, "idProduct"))
		if strings.TrimSpace(string(v)) == "27c6" && strings.TrimSpace(string(p)) == "5120" {
			return true
		}
	}
	return false
}

// Snapshot reports two counters, both of which matter only as differences.
//
// The i8042 interrupt counts (summed over CPUs) watch the keyboard half of the
// EC: a key press that does not move them means the EC sent nothing, as opposed
// to Linux dropping it.
//
// "ec refreshes" watches the EC itself, through an interface the fingerprint
// commands do not touch. See ecRefreshCounter.
//
// The ACPI SCI count used to be logged here and no longer is. It was never a
// liveness signal: it stood still at 300 through all of Run 2 and at 118 through
// both 18:2x runs, every one of them healthy. See docs/acpi.md.
func (h *linuxHost) Snapshot() string {
	var parts []string
	if f, err := os.Open("/proc/interrupts"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if !strings.Contains(line, "i8042") {
				continue
			}
			fields := strings.Fields(line)
			var sum uint64
			for _, fld := range fields[1:] {
				n, err := strconv.ParseUint(fld, 10, 64)
				if err != nil {
					break
				}
				sum += n
			}
			parts = append(parts, fmt.Sprintf("i8042 irq%s=%d", strings.TrimSuffix(fields[0], ":"), sum))
		}
		if err := sc.Err(); err != nil {
			parts = append(parts, "interrupts unreadable: "+err.Error())
		}
		f.Close()
	}
	if n, ok := h.ec.count(); ok {
		parts = append(parts, fmt.Sprintf("ec refreshes=%d", n))
	} else {
		parts = append(parts, "ec refreshes=? (no battery to watch)")
	}
	if len(parts) == 0 {
		return "no counters readable"
	}
	return strings.Join(parts, " ")
}

// Mark appends msg to the kernel log. Failure is ignored: the markers are a
// convenience for reading the journal afterwards, not part of the result.
func (h *linuxHost) Mark(msg string) {
	if !h.marks {
		return
	}
	f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "<5>goodix-probe: %s\n", msg)
}

// ecRefreshCounter counts how often the EC updates the battery block it keeps in
// its own RAM. It is a liveness signal for the EC firmware in the same idiom as
// the i8042 interrupt count: the absolute value means nothing, a value that
// stops advancing does.
//
// It reaches the EC by a path the fingerprint commands never touch. ACPI's
// battery methods read BAPR/BARC/BAPV straight out of the EC's memory-mapped RAM
// window (docs/acpi.md), so a sample is a plain memory read of bytes the EC
// firmware keeps up to date. It costs the EC nothing and cannot disturb it, and
// when the firmware stops running the values freeze rather than erroring —
// which is exactly the distinction a wedge needs.
//
// Measured idle on AC, 2026-09-20: the tuple changed 7 times in 60 s, with one
// gap of 28 s. So a single unchanged sample proves nothing. A counter that has
// not moved between two checks a minute apart is the finding.
type ecRefreshCounter struct {
	read func() (string, bool)

	mu      sync.Mutex
	last    string
	seen    bool
	changes uint64
}

func (c *ecRefreshCounter) sample() {
	v, ok := c.read()
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen && v != c.last {
		c.changes++
	}
	c.last, c.seen = v, true
}

// count returns the number of changes seen so far, and whether the EC values
// could be read at all.
func (c *ecRefreshCounter) count() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changes, c.seen
}

// poll samples until the process exits. The probe is short-lived, so there is
// nothing to stop it for.
func (c *ecRefreshCounter) poll(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		c.sample()
	}
}

// batteryFields are the EC-maintained values worth watching. charge_now and
// energy_now are alternatives — whichever the driver exposes is used.
var batteryFields = []string{"voltage_now", "current_now", "charge_now", "energy_now", "capacity"}

// readBatteryTuple joins every readable battery field into one string. Any
// change anywhere in it counts as a refresh.
func readBatteryTuple() (string, bool) {
	dirs, _ := filepath.Glob("/sys/class/power_supply/BAT*")
	var parts []string
	for _, d := range dirs {
		for _, f := range batteryFields {
			if b, err := os.ReadFile(filepath.Join(d, f)); err == nil {
				parts = append(parts, strings.TrimSpace(string(b)))
			}
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " "), true
}

// assumeKeysHost stands in for the keyboard in --replay runs without root:
// every check passes.
type assumeKeysHost struct{}

func (assumeKeysHost) WaitKey(time.Duration) (bool, error) { return true, nil }
func (assumeKeysHost) SensorPresent() bool                 { return false }
func (assumeKeysHost) Snapshot() string                    { return "not observed (--assume-keys)" }
func (assumeKeysHost) Mark(string)                         {}

// syncWriter writes to a file and flushes it to disk after every write, so the
// log survives the machine being powered off mid-run.
type syncWriter struct{ f *os.File }

func (w syncWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.f.Sync()
}

var errAssumeKeysLive = errors.New("--assume-keys is only allowed with --replay")
