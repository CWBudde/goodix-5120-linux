package main

import (
	"bytes"
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

// TestUploadConfigIsNotAStep guards the one outbound frame in the catalogue
// whose bytes nobody has: the driver log truncates the 224-byte 0x90 config.
// Until a Disable/Enable capture on Windows records it, no code may send a
// guessed one.
func TestUploadConfigIsNotAStep(t *testing.T) {
	const uploadConfig proto.Opcode = 0x90
	for _, st := range steps {
		if st.cmd == uploadConfig {
			t.Fatal("upload_config_mcu is a probe step, but its payload is not on record")
		}
	}
	for _, st := range vendorInit {
		if st.cmd == uploadConfig && st.known() {
			t.Error("vendorInit carries bytes for upload_config_mcu; the driver log truncates them, " +
				"so any bytes here are invented")
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
