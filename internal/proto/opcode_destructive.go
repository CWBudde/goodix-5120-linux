//go:build goodix_destructive

package proto

// destructiveEnabled reports whether this build registers flash-writing
// opcodes.
const destructiveEnabled = true

// DANGER: these commands write the device flash. Writing 5110 firmware to a
// 5120 chip can permanently brick it. They exist only in builds carrying the
// goodix_destructive build tag; a default build cannot name or emit them.
func init() {
	register(0xf0, "write_firmware", ClassDestructive)
	register(0xe0, "preset_psk_write", ClassDestructive)
}
