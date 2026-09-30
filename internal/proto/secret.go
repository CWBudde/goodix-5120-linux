package proto

// secretReplies names the commands whose replies must never be printed
// (PLAN.md, "Never publish"). The 0xe4 reply carries a hash of the device PSK;
// the 0xa6 reply is the device OTP, from which the DAC values and the FDT
// delta are derived. The requests are not secret — their payloads are the
// vendor's, in cmd/goodix-probe/vendor.go.
//
// It is a deny list in one place, so adding a new way to print bytes cannot
// quietly reopen one of these: goodix-pcap refuses to show them, and the
// probe's and the transport's logs withhold them (Run 21 printed both in
// full before this existed).
var secretReplies = map[Opcode]string{
	0xe4: "the reply carries a hash of the device PSK",
	0xa6: "the reply is the device OTP",
}

// SecretReply reports whether op's reply must not be printed, and why.
func SecretReply(op Opcode) (why string, secret bool) {
	why, secret = secretReplies[op]
	return why, secret
}

// SecretPack reports whether raw, one transfer read from the device, is a
// command message whose payload must not be printed. It reads only the pack
// flags and the command byte, so it still answers for a transfer whose length
// or checksum is wrong — a malformed secret is still a secret.
func SecretPack(raw []byte) (op Opcode, why string, secret bool) {
	if len(raw) <= packHeaderLen || raw[0] != FlagMessage {
		return 0, "", false
	}
	op = Opcode(raw[packHeaderLen])
	why, secret = SecretReply(op)
	return op, why, secret
}
