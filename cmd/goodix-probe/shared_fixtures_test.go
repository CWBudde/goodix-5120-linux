package main

import (
	"bytes"
	"fmt"
	"testing"

	"goodix5120/internal/proto"
	"goodix5120/internal/testfixtures"
)

// C and Go must each agree with the independent corpus. Comparing them only
// with each other could bless a shared transcription error.
func TestSharedInitFixtures(t *testing.T) {
	c := testfixtures.Load(t)
	refs := c.Prefix("init.")
	if len(refs) != len(vendorInit) {
		t.Fatalf("init has %d steps, want %d", len(vendorInit), len(refs))
	}
	script := vendorInitScript()
	if len(script) != len(refs) {
		t.Fatal("incomplete replay")
	}
	for i, s := range refs {
		t.Run(s.Name, func(t *testing.T) {
			if s.Name != fmt.Sprintf("init.%02d", i) {
				t.Fatal("unordered init reference")
			}
			cmd := proto.Opcode(s.Hex(t, "cmd")[0])
			want := s.Hex(t, "payload")
			for _, got := range []step{vendorInit[i], {cmd: script[i].Cmd, payload: script[i].Payload}} {
				if got.cmd != cmd || !bytes.Equal(got.payload, want) {
					t.Fatalf("init %d = %02x %x, want %02x %x", i, got.cmd, got.payload, cmd, want)
				}
			}
			_, secret := proto.SecretReply(cmd)
			if secret != (s.Int(t, "secret") == 1) {
				t.Fatal("secret classification drift")
			}
			var modes []string
			var data []byte
			for _, raw := range script[i].Responses {
				flags, body, err := proto.DecodePack(raw)
				if err != nil {
					t.Fatal(err)
				}
				if flags == proto.FlagTLSData {
					modes = append(modes, "tls")
					continue
				}
				rc, payload, err := proto.DecodeMessage(body)
				if err != nil {
					t.Fatal(err)
				}
				if rc == proto.AckCmd {
					ack, status, err := proto.DecodeAck(rc, payload)
					if err != nil || ack != cmd || status != 1 {
						t.Fatal("wrong ACK")
					}
					modes = append(modes, "ack")
				} else {
					if rc != cmd {
						t.Fatal("wrong reply opcode")
					}
					modes = append(modes, "data")
					data = payload
				}
			}
			mode := "none"
			if len(modes) == 1 {
				mode = modes[0]
			} else if len(modes) == 2 {
				mode = modes[0] + "-" + modes[1]
			} else if len(modes) > 2 {
				t.Fatal("extra reply")
			}
			if mode != s.String(t, "reply") || !bytes.Equal(data, s.Hex(t, "data")) {
				t.Fatalf("reply = %s %x, want %s %x", mode, data, s.String(t, "reply"), s.Hex(t, "data"))
			}
		})
	}
	for _, s := range append(c.Prefix("loop."), c.Section(t, "health")) {
		st, ok := stepFor(proto.Opcode(s.Hex(t, "cmd")[0]))
		if !ok || !bytes.Equal(st.payload, s.Hex(t, "payload")) {
			t.Fatalf("%s payload drift: %02x %x, want %02x %x (found %t)", s.Name, st.cmd, st.payload, s.Hex(t, "cmd")[0], s.Hex(t, "payload"), ok)
		}
	}
	if sensorWidth != c.Section(t, "image").Int(t, "width") || sensorHeight != c.Section(t, "image").Int(t, "height") {
		t.Fatal("sensor geometry drift")
	}
}
