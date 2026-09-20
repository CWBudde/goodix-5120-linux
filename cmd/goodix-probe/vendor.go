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
//
// Since the 224-byte `0x90` config was recovered from gfusb.dll every entry in
// vendorInit answers true, and safety_test.go pins that. The guard stays because
// it fails closed: nil means "no bytes", and the callers below — bisectable,
// printFrame, and the Phase 4 byte-for-byte gate — must refuse such a step
// rather than put an empty frame on the wire. An empty frame is exactly what
// wedged the EC three times.
func (s step) known() bool { return s.payload != nil }

// mcuStateRequest is the payload of `0xae`: the literal 0x55 followed by a host
// timestamp in milliseconds, little endian. The vendor sends a live counter;
// the EC has never been observed to react to its value, so a fixed one is used
// here to keep frames reproducible.
var mcuStateRequest = []byte{0x55, 0xa2, 0x52, 0x00, 0x00}

// uploadConfigPayload is the 224-byte argument of `0x90` (upload_config_mcu):
// the register script the vendor driver writes into the sensor MCU on every
// init. Observed, not transcribed from upstream — goodix-fp-dump has no such
// blob. docs/protocol.md, "The 224-byte `0x90` config — recovered (observed,
// 2026-09-20)", is the source of truth; these bytes are that section's.
//
// Recovered statically from the vendor's `gfusb.dll`, where it appears 19 times
// byte-identical (first at file offset 0xd04e2). The driver's own ETW debug log
// truncates the frame at 57 payload bytes, so the log alone could never have
// produced it, and no Windows Disable/Enable capture was needed in the end.
//
// The 224-byte window is pinned by the vendor's own checksum convention:
// sum(payload) & 0xff == 0xaa. A window off by a byte in either direction fails
// that, which is what makes the extraction more than a plausible-looking blob.
// safety_test.go re-checks it, along with the logged 57-byte prefix.
//
// It is a write script, not a register map: 0x5c, 0x66, 0x7c and 0x12a each
// recur with different values, so order matters and it cannot be reordered or
// deduplicated. Nothing here is secret — no key, no OTP, no biometric data.
var uploadConfigPayload = []byte{
	0x70, 0x11, 0x60, 0x71, 0x00, 0x71, 0x2c, 0x9d,
	0x1c, 0xb9, 0x18, 0xd1, 0x00, 0xd1, 0x00, 0xd1,
	0x00, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x04,
	0x00, 0x84, 0x00, 0x15, 0xb3, 0x86, 0x00, 0x00,
	0xc4, 0x88, 0x00, 0x00, 0xba, 0x8a, 0x00, 0x00,
	0xb2, 0x8c, 0x00, 0x00, 0xaa, 0x8e, 0x00, 0x00,
	0xc1, 0x90, 0x00, 0xbb, 0xbb, 0x92, 0x00, 0xb1,
	0xb1, 0x94, 0x00, 0x00, 0xa8, 0x96, 0x00, 0x00,
	0xb6, 0x98, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00,
	0x00, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00,
	0x00, 0xd6, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00,
	0x00, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00,
	0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78,
	0x56, 0x74, 0x00, 0x34, 0x12, 0x20, 0x00, 0x10,
	0x40, 0x2a, 0x01, 0x82, 0x03, 0x22, 0x00, 0x01,
	0x20, 0x24, 0x00, 0x14, 0x00, 0x80, 0x00, 0x01,
	0x00, 0x5c, 0x00, 0x00, 0x01, 0x56, 0x00, 0x04,
	0x20, 0x58, 0x00, 0x03, 0x02, 0x32, 0x00, 0x0c,
	0x02, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00,
	0x58, 0x82, 0x00, 0x80, 0x15, 0x2a, 0x01, 0x08,
	0x00, 0x5c, 0x00, 0x80, 0x00, 0x54, 0x00, 0x10,
	0x01, 0x62, 0x00, 0x04, 0x03, 0x64, 0x00, 0x19,
	0x00, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00,
	0x58, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x00,
	0x01, 0x52, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00,
	0x01, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00,
	0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x15,
}

// vendorInit is the Windows driver's initialisation sequence, transcribed from
// its own ETW debug log (docs/protocol.md, "Init sequence"). It was identical
// across all nine complete inits in the log. The one payload the log does not carry in
// full, the 224-byte `0x90` config, came out of gfusb.dll instead — see
// uploadConfigPayload above. Every payload here is now on record.
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
	{0x90, uploadConfigPayload, "upload config",
		"224 bytes, recovered from gfusb.dll (docs/protocol.md); sum & 0xff == 0xaa pins the length"},
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
