package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"goodix5120/internal/proto"
	"goodix5120/internal/transport"
)

// The tests below guard the probe binary itself. internal/proto and
// internal/transport each verify their own invariants; what is checked here is
// that this command — the one that actually talks to the hardware — assembles
// those pieces into something that cannot write to the device.

// TestStepsAreAllSafe fails if anyone adds a step to the probe sequence that is
// not read-only. The probe's whole justification for running against
// irreplaceable hardware is that it cannot alter it.
func TestStepsAreAllSafe(t *testing.T) {
	for _, step := range steps {
		class, ok := step.cmd.Class()
		if !ok {
			t.Errorf("step 0x%02x is not registered in proto; the transport would refuse it at runtime", byte(step.cmd))
			continue
		}
		if class != proto.ClassSafe {
			t.Errorf("step %s (0x%02x) is %s, but the probe must only send read-only commands",
				step.cmd.Name(), byte(step.cmd), class)
		}
		if err := step.cmd.CheckPayload(len(step.payload)); err != nil {
			t.Errorf("step %s (0x%02x) carries a payload the transport would refuse: %v",
				step.cmd.Name(), byte(step.cmd), err)
		}
	}
}

// TestStepPayloadsMatchVendorInit is the PLAN.md Phase 4 gate expressed as a
// test: "each planned command matches the vendor sequence byte for byte
// (opcode *and* payload)". Every command the probe sends live must be one the
// Windows driver sends, with identical bytes.
func TestStepPayloadsMatchVendorInit(t *testing.T) {
	for _, st := range steps {
		var found bool
		for _, v := range vendorInit {
			if v.cmd == st.cmd && v.known() && bytes.Equal(v.payload, st.payload) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("step %s (0x%02x) payload %x does not match any vendor frame; "+
				"the probe may only send what the vendor driver sends",
				st.cmd.Name(), byte(st.cmd), st.payload)
		}
	}
}

// TestVendorInitPayloadsSatisfyTheirRules checks the catalogue against the
// registry. A mismatch means one of the two transcribed the vendor log wrong,
// and the payload rules are what stop the EC being handed a frame it cannot
// survive.
func TestVendorInitPayloadsSatisfyTheirRules(t *testing.T) {
	for i, st := range vendorInit {
		if !st.known() {
			continue
		}
		if err := st.cmd.CheckPayload(len(st.payload)); err != nil {
			t.Errorf("vendorInit[%d] %s (0x%02x): %v", i, st.cmd.Name(), byte(st.cmd), err)
		}
	}
}

// opUploadConfig (upload_config_mcu, 0x90) is declared in bisect.go, next to the
// flag that admits it. Its 224-byte payload is on record as of 2026-09-20, but it
// is ClassStateChanging and nothing has ever sent it from Linux, so it stays out
// of `steps` and needs --allow-90 even in a bisect run.

// uploadConfigLogPrefix is the first 57 payload bytes of the `0x90` frame as
// the vendor driver's own ETW debug log prints them — the log truncates there,
// which is why the full config had to come out of gfusb.dll instead.
//
// Written here as hex, separately from the byte literal in vendor.go, so the
// two must be changed together. Be clear about how independent that is: the raw
// ETW log is not in this repository, so both literals were taken from
// docs/protocol.md, which records the DLL blob and states that the log agrees
// with its first 57 bytes. What this constant buys is therefore not a second
// reading of the log but a second, differently-encoded copy of the same claim:
// a re-extraction that shifts the window has to justify itself here too.
const uploadConfigLogPrefix = "7011607100712c9d1cb918d100d100d100ba000180ca000400840015b3860000" +
	"c4880000ba8a0000b28c0000aa8e0000c19000bbbb9200b1b1"

// TestUploadConfigIsNotAStep keeps `0x90` out of the live sequence. Knowing the
// bytes is not permission to send them: writing a register script to the MCU is
// state-changing, and PLAN.md Phase 4 gates it on a live run of its own.
func TestUploadConfigIsNotAStep(t *testing.T) {
	for _, st := range steps {
		if st.cmd == opUploadConfig {
			t.Fatal("upload_config_mcu is a probe step; it is state-changing and Phase 4 has not cleared it")
		}
	}
}

// TestUploadConfigMatchesTheRecoveredBlob checks the catalogue's `0x90` payload
// against the three properties docs/protocol.md used to establish it. Each one
// fails if the 224-byte window extracted from gfusb.dll is off by a byte, so
// together they are what stops a re-extraction silently shifting.
func TestUploadConfigMatchesTheRecoveredBlob(t *testing.T) {
	var payload []byte
	var found bool
	for _, st := range vendorInit {
		if st.cmd == opUploadConfig {
			payload, found = st.payload, true
			break
		}
	}
	if !found {
		t.Fatal("vendorInit has no upload_config_mcu entry; the vendor sends one on every init")
	}

	// 1. Present and exactly 224 bytes. A nil payload here is the old state of
	// this file, when nobody had the bytes; a different length means the window
	// moved, and proto's PayloadExactly(224) rule would refuse the frame.
	if payload == nil {
		t.Fatal("upload_config_mcu carries no payload; it was recovered on 2026-09-20 (docs/protocol.md)")
	}
	if len(payload) != 224 {
		t.Fatalf("upload_config_mcu payload is %d bytes, want 224", len(payload))
	}

	// 2. The vendor's message-checksum convention. This is the check that pins
	// the length: sum over 223 or 225 bytes of the DLL's .rdata does not land
	// on 0xaa, so an off-by-one extraction cannot pass it.
	var sum byte
	for _, b := range payload {
		sum += b
	}
	if sum != 0xaa {
		t.Errorf("sum(payload) & 0xff = 0x%02x, want 0xaa; the 224-byte window is wrong", sum)
	}

	// 3. Agreement with the debug log. The log and the DLL are independent
	// artefacts; if the extracted blob were a different structure that happens
	// to be 224 bytes and sum to 0xaa, this is what would catch it. It also
	// catches a shift at the START of the window, which the checksum alone
	// would not if the shift kept the sum.
	want, err := hex.DecodeString(uploadConfigLogPrefix)
	if err != nil {
		t.Fatalf("uploadConfigLogPrefix is not valid hex: %v", err)
	}
	if len(want) != 57 {
		t.Fatalf("uploadConfigLogPrefix is %d bytes, want the 57 the driver log prints", len(want))
	}
	if !bytes.Equal(payload[:57], want) {
		t.Errorf("the first 57 payload bytes are %x,\nbut the driver log shows %x", payload[:57], want)
	}
}

// TestVendorInitPayloadsAreAllOnRecord pins what is new as of 2026-09-20: the
// whole 14-frame init sequence is known, byte for byte. Until the `0x90` config
// came out of gfusb.dll, one entry was nil and the code had to work around it
// everywhere. Reintroducing a nil should cost an argument, not a silent edit.
func TestVendorInitPayloadsAreAllOnRecord(t *testing.T) {
	for i, st := range vendorInit {
		if !st.known() {
			t.Errorf("vendorInit[%d] %s (0x%02x) has no payload; every vendor frame is on record "+
				"(docs/protocol.md, \"Init sequence\") and an empty frame is what wedged the EC",
				i, st.cmd.Name(), byte(st.cmd))
		}
	}
}

// TestDestructiveOpcodesUnreachable asserts the flash-writing opcodes are not
// merely unused here but genuinely absent from this build. Writing 5110
// firmware to a 5120 can permanently brick the sensor.
func TestDestructiveOpcodesUnreachable(t *testing.T) {
	for _, op := range []proto.Opcode{0xf0, 0xe0} {
		if _, ok := op.Class(); ok {
			t.Errorf("opcode 0x%02x is registered in a default build; it must exist only under the goodix_destructive build tag", byte(op))
		}
	}
}

// TestTransportRefusesUnsafeCommands exercises the enforcement end to end,
// through the same Options value main() constructs, rather than trusting that
// the ceiling was wired up correctly.
func TestTransportRefusesUnsafeCommands(t *testing.T) {
	tr := transport.NewReplay(nil, transport.Options{Ceiling: proto.ClassSafe})
	defer tr.Close()

	cases := []struct {
		name string
		cmd  proto.Opcode
	}{
		{"state-changing reset", 0xa2},
		{"state-changing mcu_get_image", 0x20},
		{"preset_psk_read, wedges the EC (Run 2)", 0xe4},
		{"destructive write_firmware (unregistered here)", 0xf0},
		{"destructive preset_psk_write (unregistered here)", 0xe0},
		{"arbitrary unknown byte", 0x7b},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tr.Send(tc.cmd, nil)
			if err == nil {
				t.Fatalf("Send(0x%02x) was permitted under a safe ceiling", byte(tc.cmd))
			}
			if !errors.Is(err, transport.ErrRefused) {
				t.Fatalf("Send(0x%02x) failed with %v, want an error wrapping ErrRefused", byte(tc.cmd), err)
			}
		})
	}
}

// TestReplayScriptMatchesSteps keeps the offline rehearsal honest: if a step is
// added without a corresponding scripted response, --replay would silently stop
// covering the full sequence.
func TestReplayScriptMatchesSteps(t *testing.T) {
	script := run1Script()
	if len(script) != len(steps) {
		t.Fatalf("replay script has %d exchanges for %d steps", len(script), len(steps))
	}
	for i, ex := range script {
		if ex.Cmd != steps[i].cmd {
			t.Errorf("script[%d] is 0x%02x, want 0x%02x", i, byte(ex.Cmd), byte(steps[i].cmd))
		}
		if !bytes.Equal(ex.Payload, steps[i].payload) {
			t.Errorf("script[%d] expects payload %x, but the probe sends %x",
				i, ex.Payload, steps[i].payload)
		}
	}
}
