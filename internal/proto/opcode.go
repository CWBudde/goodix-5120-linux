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
	name    string
	class   Class
	payload PayloadRule
}

// registry holds every opcode this build knows about. It is populated by
// package initialisation only and is never mutated afterwards, so concurrent
// reads need no synchronisation.
var registry = map[Opcode]opcodeInfo{}

// register adds an opcode to the registry. It panics on a duplicate
// registration, which can only be a programming error.
//
// payload is a required argument rather than an option with a default, because
// omitting the rule is the exact mistake that wedged the EC: this project sent
// 0xe4 with no payload because nothing in the code knew it took one. Use
// PayloadUnknown() to say so explicitly when the vendor driver has never been
// seen to send the opcode.
func register(op Opcode, name string, class Class, payload PayloadRule) {
	if _, dup := registry[op]; dup {
		panic(fmt.Sprintf("proto: opcode %#x registered twice", byte(op)))
	}
	registry[op] = opcodeInfo{name: name, class: class, payload: payload}
}

func init() {
	// Read-only commands.
	//
	// nop is the one opcode with no rule. Upstream sends four zero bytes, this
	// project has only ever sent it empty, and the vendor driver never sends it
	// at all ("not to send nop for ITE EC projects"), so there is nothing to
	// copy. It stays registered for the framing tests.
	register(0x00, "nop", ClassSafe, PayloadUnknown())
	register(0xa8, "firmware_version", ClassSafe, PayloadExactly(2)) // 00 00
	register(0xa6, "read_otp", ClassSafe, PayloadExactly(2))         // 00 00; empty got no reply in Run 1
	register(0xae, "get_mcu_state", ClassSafe, PayloadExactly(5))    // 55 + uint32 LE host timestamp
	register(0x82, "read_register", ClassSafe, PayloadExactly(5))    // 00 00 00 04 00 -> chip ID 0x2504

	// Commands that alter runtime state but do not write flash.
	//
	// preset_psk_read only reads, but on the 27c6:5120 an 0xe4 with an EMPTY
	// payload wedges the embedded controller (ACK, then silence, then a dead
	// keyboard; Runs 1, 2 and 4 in docs/protocol.md). Run 4 sent it alone, so no
	// other command is involved. The vendor's 8-byte argument is answered
	// normally. Classed by what it does to the device, not by its name.
	register(0xe4, "preset_psk_read", ClassStateChanging, PayloadExactly(8))         // 03 00 02 bb 00 00 00 00
	register(0x96, "enable_chip", ClassStateChanging, PayloadExactly(2))             // 01 02
	register(0xa2, "reset", ClassStateChanging, PayloadExactly(2))                   // 01 14
	register(0x70, "mcu_switch_to_idle_mode", ClassStateChanging, PayloadExactly(2)) // 14 00
	register(0x98, "set_dac", ClassStateChanging, PayloadExactly(8))                 // c8 0b be 00 bc 00 bc 00, from the OTP
	register(0x90, "upload_config_mcu", ClassStateChanging, PayloadExactly(224))
	register(0xd0, "request_tls_connection", ClassStateChanging, PayloadExactly(2)) // 00 00
	register(0xd4, "tls_successfully_established", ClassStateChanging, PayloadExactly(2))
	register(0x20, "mcu_get_image", ClassStateChanging, PayloadExactly(2)) // 01 00
	register(0x50, "nav_mode", ClassStateChanging, PayloadExactly(2))      // 01 00; from the driver log only

	// Finger-detect arming. Each one puts the EC into a mode where it emits
	// events unprompted, so none of them is a read.
	register(0x32, "fdt_down", ClassStateChanging, PayloadExactly(16))   // 0c 01 + 6x(80 xx) + uint16 timestamp
	register(0x34, "fdt_up", ClassStateChanging, PayloadExactly(14))     // 0e 01 + 6x(80 xx)
	register(0x36, "fdt_manual", ClassStateChanging, PayloadExactly(14)) // 0d 01 + 6x(80 xx)

	// check_firmware is registered but never sent: the vendor driver skips the
	// whole firmware path on this part ("no firmware update for EC projects"),
	// so its payload is unknown and nothing here may guess one.
	register(0xf4, "check_firmware", ClassStateChanging, PayloadUnknown())

	// 0xd2 is deliberately absent. PLAN.md lists it speculatively, but it
	// appears in neither the vendor driver's nine complete inits nor either USB
	// capture. Registering an opcode nobody has observed would widen the safety
	// boundary for nothing.

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

// PayloadRule returns the registered payload rule for the opcode. ok is false
// if the opcode is unregistered, mirroring Class.
func (o Opcode) PayloadRule() (PayloadRule, bool) {
	info, ok := registry[o]
	if !ok {
		return PayloadRule{}, false
	}
	return info.payload, true
}

// CheckPayload reports whether an n-byte payload may be sent with this opcode.
// An unregistered opcode always fails: an unknown command byte has unknown
// arguments, and guessing is what this package exists to prevent.
func (o Opcode) CheckPayload(n int) error {
	rule, ok := o.PayloadRule()
	if !ok {
		return fmt.Errorf("%w: opcode 0x%02x is unregistered, so its arguments are unknown", ErrPayload, byte(o))
	}
	return rule.Check(n)
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
