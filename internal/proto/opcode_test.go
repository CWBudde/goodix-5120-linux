package proto

import (
	"sort"
	"testing"
)

func TestClassString(t *testing.T) {
	tests := []struct {
		class Class
		want  string
	}{
		{ClassSafe, "safe"},
		{ClassStateChanging, "state-changing"},
		{ClassDestructive, "destructive"},
		{Class(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.class.String(); got != tt.want {
				t.Fatalf("Class(%d).String() = %q, want %q", uint8(tt.class), got, tt.want)
			}
		})
	}
}

func TestOpcodeRegistry(t *testing.T) {
	tests := []struct {
		op    Opcode
		name  string
		class Class
	}{
		{0x00, "nop", ClassSafe},
		{0xa8, "firmware_version", ClassSafe},
		{0xa6, "read_otp", ClassSafe},
		{0xe4, "preset_psk_read", ClassStateChanging},
		{0x96, "enable_chip", ClassStateChanging},
		{0xa2, "reset", ClassStateChanging},
		{0x70, "mcu_switch_to_idle_mode", ClassStateChanging},
		{0x90, "upload_config_mcu", ClassStateChanging},
		{0xd0, "request_tls_connection", ClassStateChanging},
		{0x20, "mcu_get_image", ClassStateChanging},
		{0xf4, "check_firmware", ClassStateChanging},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.op.Name(); got != tt.name {
				t.Fatalf("Opcode(%#x).Name() = %q, want %q", byte(tt.op), got, tt.name)
			}
			class, ok := tt.op.Class()
			if !ok {
				t.Fatalf("Opcode(%#x).Class() ok = false, want true", byte(tt.op))
			}
			if class != tt.class {
				t.Fatalf("Opcode(%#x).Class() = %v, want %v", byte(tt.op), class, tt.class)
			}
		})
	}
}

func TestOpcodeUnregistered(t *testing.T) {
	for _, op := range []Opcode{0x01, 0x42, 0xff} {
		if got := op.Name(); got != "" {
			t.Fatalf("Opcode(%#x).Name() = %q, want \"\"", byte(op), got)
		}
		if _, ok := op.Class(); ok {
			t.Fatalf("Opcode(%#x).Class() ok = true, want false", byte(op))
		}
	}
}

func TestRegisteredIsSorted(t *testing.T) {
	ops := Registered()
	if len(ops) == 0 {
		t.Fatal("Registered() returned no opcodes")
	}
	if !sort.SliceIsSorted(ops, func(i, j int) bool { return ops[i] < ops[j] }) {
		t.Fatalf("Registered() is not sorted: % x", ops)
	}
	seen := make(map[Opcode]bool, len(ops))
	for _, op := range ops {
		if seen[op] {
			t.Fatalf("Registered() contains duplicate opcode %#x", byte(op))
		}
		seen[op] = true
		if op.Name() == "" {
			t.Fatalf("Registered() opcode %#x has no name", byte(op))
		}
	}
}

func TestRegisteredContainsAllSafeAndStateChanging(t *testing.T) {
	want := []Opcode{0x00, 0x20, 0x70, 0x90, 0x96, 0xa2, 0xa6, 0xa8, 0xd0, 0xe4, 0xf4}
	got := Registered()
	set := make(map[Opcode]bool, len(got))
	for _, op := range got {
		set[op] = true
	}
	for _, op := range want {
		if !set[op] {
			t.Fatalf("Registered() is missing opcode %#x", byte(op))
		}
	}
}

// TestNoDestructiveOpcodesInDefaultBuild is the central safety guarantee of the
// project: writing 5110 firmware to this 5120 chip can permanently brick it, so
// a default build must contain no way to name or emit those commands.
func TestNoDestructiveOpcodesInDefaultBuild(t *testing.T) {
	if destructiveEnabled {
		t.Skip("built with -tags goodix_destructive")
	}

	for _, op := range Registered() {
		class, ok := op.Class()
		if !ok {
			t.Fatalf("Registered() opcode %#x is not resolvable", byte(op))
		}
		if class == ClassDestructive {
			t.Fatalf("destructive opcode %#x (%s) is registered in a default build", byte(op), op.Name())
		}
	}

	for _, op := range []Opcode{0xf0, 0xe0} {
		if _, ok := op.Class(); ok {
			t.Fatalf("Opcode(%#x).Class() ok = true in a default build, want false", byte(op))
		}
		if name := op.Name(); name != "" {
			t.Fatalf("Opcode(%#x).Name() = %q in a default build, want \"\"", byte(op), name)
		}
	}
}

func TestDestructiveOpcodesOnlyWithBuildTag(t *testing.T) {
	if !destructiveEnabled {
		t.Skip("default build")
	}

	tests := []struct {
		op   Opcode
		name string
	}{
		{0xf0, "write_firmware"},
		{0xe0, "preset_psk_write"},
	}

	for _, tt := range tests {
		class, ok := tt.op.Class()
		if !ok {
			t.Fatalf("Opcode(%#x).Class() ok = false with the destructive build tag", byte(tt.op))
		}
		if class != ClassDestructive {
			t.Fatalf("Opcode(%#x).Class() = %v, want ClassDestructive", byte(tt.op), class)
		}
		if got := tt.op.Name(); got != tt.name {
			t.Fatalf("Opcode(%#x).Name() = %q, want %q", byte(tt.op), got, tt.name)
		}
	}
}
