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
	h := &linuxHost{keys: make(chan struct{}, 64), done: make(chan error, 1), marks: marks}
	go h.read(f)
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

// Snapshot reports the i8042 interrupt counts (summed over CPUs) and the ACPI
// SCI count. A key press that does not move the i8042 count means the EC sent
// nothing, as opposed to Linux dropping it.
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
	if b, err := os.ReadFile("/sys/firmware/acpi/interrupts/sci"); err == nil {
		if fields := strings.Fields(string(b)); len(fields) > 0 {
			parts = append(parts, "acpi sci="+fields[0])
		}
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
