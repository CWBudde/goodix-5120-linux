package evtx

import (
	"fmt"
	"regexp"
	"strings"
)

// The driver's debug log writes every hex dump as `<label>::0x<hex digits>`,
// except where it writes one colon instead of two. The label is what the dump
// is: `Send data::`, `data::`, `Got sensor OTP::`, `received fdt base::`,
// `test::`, `sensorid:`.
//
// One colon or two, because the single-colon spelling is not cosmetic: the only
// dump in this log that leaked past a `::`-only pattern was `sensorid:0x…`,
// 32 bytes of the OTP under a label that says nothing about the OTP.
var hexDump = regexp.MustCompile(`(?i)([A-Za-z_ ]*):{1,2}0x([0-9a-f]+)`)

// Reasons the two withheld dumps are withheld. They are the same two payloads
// cmd/goodix-pcap refuses to print, for the same reasons, and the wording is
// kept close to that deny list on purpose: one device, one rule.
const (
	reasonOTP = "the device OTP"
	reasonPSK = "a hash of the device PSK"
)

// secretReply keys the refusal on the opcode a received message starts with.
// A `data::` dump is a whole message — [cmd][len LE16][payload][checksum] — so
// its first byte names what the payload is.
//
// Observed, 2026-09-20: this log holds nine `data::0xe42a00…` runs of 45 bytes
// and nine `data::0xa641…` runs of 68 bytes, one of each per complete init.
// Those are the full 41-byte 0xe4 reply and the full 64-byte 0xa6 reply, not
// truncations. The log's own `recvd data cmd-len: 0xe4-42` lines state the
// lengths and stay printable; only the bytes go.
var secretReply = map[string]string{
	"e4": reasonPSK,
	"a6": reasonOTP,
}

// keepMessageHead is how much of a withheld `data::` dump survives: the opcode
// and its little-endian 16-bit length, six hex digits. Both are already stated
// in clear by the `recvd data cmd-len:` line next to it, so withholding them
// would hide nothing and cost the reader the ability to tell which reply was
// suppressed.
const keepMessageHead = 6

// Redact removes the hex dumps this package refuses to reproduce, and reports
// whether it removed any.
//
// It runs inside Scan, before a Record exists. That placement is the point:
// cmd/goodix-pcap keeps its deny list at the print site, which works only for
// as long as every print site remembers to consult it, and this log is going to
// grow more print sites. Here there is no unredacted path to forget about. The
// cost is that the bytes cannot be recovered through this package at all, which
// for these two payloads is the desired cost.
//
// What is deliberately NOT withheld, having been weighed:
//   - `Send data::0xa0…`, the frames the host sends. The 224-byte 0x90 config
//     and the whole 13-frame init live here, and reproducing them is the reason
//     this tool exists. They are host-side and already in docs/protocol.md.
//   - TLS handshake records. A ClientHello random is a public nonce, and no
//     fingerprint ciphertext appears in this log at all — the sensor's image
//     data is never dumped to the debug channel (checked: no b0/b2 run of image
//     length exists in the file).
//   - `received fdt base::`, `base data sent::`, `test::`. These are sensor
//     calibration baselines taken with no finger present, truncated to 17 bytes
//     by the driver. They are not biometric and not secret.
func Redact(s string) (string, bool) {
	matches := hexDump.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s, false
	}

	var b strings.Builder
	last, changed := 0, false
	for _, m := range matches {
		label, hex := s[m[2]:m[3]], s[m[4]:m[5]]
		why, keep, deny := verdict(label, hex)
		if !deny {
			continue
		}
		b.WriteString(s[last:m[4]])
		b.WriteString(hex[:keep])
		fmt.Fprintf(&b, "[%d hex digits withheld: %s]", len(hex)-keep, why)
		last, changed = m[5], true
	}
	if !changed {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), true
}

// verdict decides one dump, returning why it is withheld and how many leading
// hex digits survive.
func verdict(label, hex string) (why string, keep int, deny bool) {
	l := strings.ToLower(strings.TrimSpace(label))

	// The OTP is dumped under five different labels — "Got sensor OTP::",
	// "got file otp::", "got OTP from driver::", "USED OTP::" and lower-case
	// variants — and under none of them does it start with the 0xa6 opcode,
	// because the driver has already unwrapped the message. Keying on the word
	// is the only thing that catches all of them.
	if strings.Contains(l, "otp") {
		return reasonOTP, 0, true
	}

	// `sensorid:0x…` is 64 hex digits — the first 32 bytes of the OTP, under a
	// label that never says so. docs/protocol.md publishes the OTP's first seven
	// characters (ASCII "S2A755.") deliberately; it does not publish this.
	if l == "sensorid" {
		return reasonOTP + " (its first 32 bytes, logged as the sensor id)", 0, true
	}

	// The opcode rule applies only to dumps of a whole message. "base data
	// sent::" and "test::" are buffers, not frames, and their first byte means
	// nothing.
	if !strings.HasSuffix(l, "data") || len(hex) < 2 {
		return "", 0, false
	}
	why, ok := secretReply[strings.ToLower(hex[:2])]
	if !ok {
		return "", 0, false
	}
	keep = keepMessageHead
	if len(hex) < keep {
		keep = len(hex)
	}
	return why, keep, true
}
