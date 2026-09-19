//go:build goodix_destructive

package transport

import (
	"errors"
	"testing"

	"goodix5120/internal/proto"
)

// Allow must never lift a destructive opcode over the ceiling, even in a build
// where destructive opcodes are registered.
func TestAllowNeverAdmitsDestructive(t *testing.T) {
	for _, op := range []proto.Opcode{0xf0, 0xe0} {
		for _, ceiling := range []proto.Class{proto.ClassSafe, proto.ClassStateChanging} {
			err := checkOpcode(op, ceiling, []proto.Opcode{op})
			if !errors.Is(err, ErrRefused) {
				t.Errorf("checkOpcode(0x%02x, %s, allow itself) = %v, want ErrRefused", byte(op), ceiling, err)
			}
		}
	}
}
