//go:build !goodix_destructive

package proto

// destructiveEnabled reports whether this build registers flash-writing
// opcodes. It is false here: the default build contains no destructive opcode.
const destructiveEnabled = false
