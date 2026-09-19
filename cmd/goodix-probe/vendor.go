package main

import "goodix5120/internal/proto"

// step is one command together with the exact payload the Windows vendor
// driver sends with it.
//
// Before this type existed the probe sent every command with a nil payload,
// which is how `0xe4` went out empty and wedged the embedded controller three
// times (docs/protocol.md, Runs 1, 2 and 4).
type step struct {
	cmd     proto.Opcode
	payload []byte // nil means the vendor's payload is not known; see note
	purpose string
	note    string // optional caveat, printed by --dry-run
}

// known reports whether the vendor's payload for this step is on record.
func (s step) known() bool { return s.payload != nil }

// mcuStateRequest is the payload of `0xae`: the literal 0x55 followed by a host
// timestamp in milliseconds, little endian. The vendor sends a live counter;
// the EC has never been observed to react to its value, so a fixed one is used
// here to keep frames reproducible.
var mcuStateRequest = []byte{0x55, 0xa2, 0x52, 0x00, 0x00}

// vendorInit is the Windows driver's initialisation sequence, transcribed from
// its own ETW debug log (docs/protocol.md, "Init sequence"). It was identical
// across all eight inits in the log.
//
// This is the single source of truth for every payload in this binary. The
// probe does NOT send it: `steps` below is the much smaller subset cleared for
// live hardware, and PLAN.md Phase 4 gates any growth of that subset on one
// command per run. vendorInit exists so `--dry-run` can print what the vendor
// sends, which is what the Phase 4 gate ("byte for byte") is checked against.
var vendorInit = []step{
	{0x96, []byte{0x01, 0x02}, "enable chip", "the driver does not wait for a reply"},
	{0xa8, []byte{0x00, 0x00}, "firmware version", ""},
	{0xae, mcuStateRequest, "get MCU state", "answers with 20 bytes and NO ACK"},
	{0xe4, []byte{0x03, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00}, "read production data",
		"data_type 0xbb020003 then a uint32 length of 0; the reply carries a hash of the device PSK"},
	{0xa2, []byte{0x01, 0x14}, "reset", ""},
	{0x82, []byte{0x00, 0x00, 0x00, 0x04, 0x00}, "read register — chip ID", "replies a2 04 25 00, i.e. 0x2504"},
	{0xa6, []byte{0x00, 0x00}, "read OTP", "64 bytes of calibration data; empty payload got no reply in Run 1"},
	{0xa2, []byte{0x01, 0x14}, "reset", "sent a second time"},
	{0x70, []byte{0x14, 0x00}, "switch MCU to idle mode", ""},
	{0x98, []byte{0xc8, 0x0b, 0xbe, 0x00, 0xbc, 0x00, 0xbc, 0x00}, "set DAC", "values derived from the OTP"},
	{0x90, nil, "upload config",
		"224 bytes, TRUNCATED in the driver log — needs a Disable/Enable capture on Windows"},
	{0xd0, []byte{0x00, 0x00}, "request TLS connection", "no ACK; the EC then opens a TLS handshake as the client"},
	{0xd4, []byte{0x00, 0x00}, "TLS established", ""},
	{0xae, mcuStateRequest, "get MCU state", "now reports isTlsConnected=1"},
}

// steps is what the probe sends to live hardware. It is deliberately one
// command.
//
// nop is gone: the vendor driver never sends it to an ITE EC ("not to send nop
// for ITE EC projects") and it drew no reply at all in Runs 2 and 3. It stays
// registered in internal/proto for the framing tests.
//
// Growing this list is a PLAN.md Phase 4 decision, one command per live run.
// safety_test.go enforces that every entry is ClassSafe and carries the
// vendor's payload, so nothing can be added here casually.
var steps = []step{
	{0xa8, []byte{0x00, 0x00}, "firmware version — expect an ACK, then the version string", ""},
}

// bisectable is the set of opcodes --steps may name. An opcode qualifies when
// it appears in vendorInit, so its payload is on record, and is ClassSafe, so
// the transport's default ceiling would pass it.
//
// preset_psk_read (0xe4) is the one exception, admitted only by --allow-e4, and
// even then it now goes out with the vendor's 8-byte argument rather than the
// empty frame that wedged the EC.
func bisectable(op proto.Opcode) (step, bool) {
	for _, s := range vendorInit {
		if s.cmd != op || !s.known() {
			continue
		}
		if class, ok := op.Class(); ok && class == proto.ClassSafe {
			return s, true
		}
		if op == opPSKRead {
			return s, true
		}
	}
	return step{}, false
}

// stepFor returns the catalogue entry for op. It backs both --steps parsing and
// the bisect log's description of each step.
func stepFor(op proto.Opcode) (step, bool) {
	for _, s := range steps {
		if s.cmd == op {
			return s, true
		}
	}
	return bisectable(op)
}
