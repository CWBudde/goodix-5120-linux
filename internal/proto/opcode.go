// Package proto implements the Goodix "wrapped" USB protocol used by the
// 27c6:5120 fingerprint sensor, transcribed from the reference Python
// implementation at github.com/goodix-fp-linux-dev/goodix-fp-dump.
//
// The package is pure: it only encodes and decodes byte slices and performs no
// I/O. Two nested framing layers are involved:
//
//	pack:    [flags:1][length:2 LE][checksum:1][payload:N]
//	message: [cmd:1][length:2 LE][payload:N][checksum:1]
//
// Commands are classified so that callers can refuse to emit anything that
// could write flash. Destructive opcodes are registered only in builds carrying
// the goodix_destructive build tag; a default build has no way to name or emit
// them.
package proto

import (
	"fmt"
	"slices"
)

// Class describes how dangerous a command is.
type Class uint8

const (
	// ClassSafe commands are read-only and cannot alter device state.
	ClassSafe Class = iota
	// ClassStateChanging commands alter runtime state but do not write flash.
	ClassStateChanging
	// ClassDestructive commands can write flash and brick the device.
	ClassDestructive
)

// String returns a human readable name for the class.
func (c Class) String() string {
	switch c {
	case ClassSafe:
		return "safe"
	case ClassStateChanging:
		return "state-changing"
	case ClassDestructive:
		return "destructive"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(c))
	}
}

// Opcode is the command byte of a protocol message.
type Opcode byte

type opcodeInfo struct {
	name  string
	class Class
}

// registry holds every opcode this build knows about. It is populated by
// package initialisation only and is never mutated afterwards, so concurrent
// reads need no synchronisation.
var registry = map[Opcode]opcodeInfo{}

// register adds an opcode to the registry. It panics on a duplicate
// registration, which can only be a programming error.
func register(op Opcode, name string, class Class) {
	if _, dup := registry[op]; dup {
		panic(fmt.Sprintf("proto: opcode %#x registered twice", byte(op)))
	}
	registry[op] = opcodeInfo{name: name, class: class}
}

func init() {
	// Read-only commands.
	register(0x00, "nop", ClassSafe)
	register(0xa8, "firmware_version", ClassSafe)
	register(0xa6, "read_otp", ClassSafe)

	// Commands that alter runtime state but do not write flash.
	//
	// preset_psk_read only reads, but on the 27c6:5120 it wedges the embedded
	// controller (ACK, then silence, then a dead keyboard; Run 1 and Run 2 in
	// docs/protocol.md). Classed by what it does to the device, not by its name.
	register(0xe4, "preset_psk_read", ClassStateChanging)
	register(0x96, "enable_chip", ClassStateChanging)
	register(0xa2, "reset", ClassStateChanging)
	register(0x70, "mcu_switch_to_idle_mode", ClassStateChanging)
	register(0x90, "upload_config_mcu", ClassStateChanging)
	register(0xd0, "request_tls_connection", ClassStateChanging)
	register(0x20, "mcu_get_image", ClassStateChanging)
	register(0xf4, "check_firmware", ClassStateChanging)

	// Destructive commands live in opcode_destructive.go behind the
	// goodix_destructive build tag and are deliberately absent here.
}

// Name returns the registered name of the opcode, or "" if it is unregistered.
func (o Opcode) Name() string {
	return registry[o].name
}

// Class returns the safety class of the opcode. ok is false if the opcode is
// unregistered, in which case the returned class is meaningless and callers
// must treat the opcode as unusable.
func (o Opcode) Class() (Class, bool) {
	info, ok := registry[o]
	if !ok {
		return 0, false
	}
	return info.class, true
}

// Registered returns every opcode known to this build, in ascending order.
func Registered() []Opcode {
	ops := make([]Opcode, 0, len(registry))
	for op := range registry {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	return ops
}
