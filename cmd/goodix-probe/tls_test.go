package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"goodix5120/internal/image"
	"goodix5120/internal/proto"
)

// The tests below guard the Phase 5 additions to this binary: the per-opcode
// unlock flags, and the --tls flag combination. Neither can be checked by the
// packages underneath, because both are about how this command assembles them.

// TestEveryAboveCeilingVendorFrameIsCatalogued pins `unlockable` against the
// vendor catalogue in both directions.
//
// Forwards, so a state-changing frame cannot be added to vendorInit or
// vendorLoop and silently become sendable with no flag and no written reason.
// Backwards, so a flag cannot outlive the frame it admits, and so a ClassSafe
// opcode does not acquire a flag that would imply it needs one.
func TestEveryAboveCeilingVendorFrameIsCatalogued(t *testing.T) {
	inCatalogue := map[proto.Opcode]bool{}
	for _, catalogue := range [][]step{vendorInit, vendorLoop} {
		for _, st := range catalogue {
			if !st.known() {
				continue
			}
			inCatalogue[st.cmd] = true
			class, ok := st.cmd.Class()
			if !ok {
				t.Errorf("catalogued opcode 0x%02x is not registered in proto", byte(st.cmd))
				continue
			}
			if class == proto.ClassSafe {
				continue
			}
			if _, found := unlockFor(st.cmd); !found {
				t.Errorf("%s (0x%02x) is %s but has no --allow-… flag; a frame above the safe ceiling "+
					"needs one, with a written reason for why it is safe enough to try",
					st.cmd.Name(), byte(st.cmd), class)
			}
		}
	}

	for _, u := range unlockable {
		if !inCatalogue[u.op] {
			t.Errorf("--%s admits 0x%02x, which is in neither vendorInit nor vendorLoop; "+
				"bisect may only send frames the vendor driver sends", u.flag, byte(u.op))
		}
		class, ok := u.op.Class()
		switch {
		case !ok:
			t.Errorf("--%s admits unregistered opcode 0x%02x", u.flag, byte(u.op))
		case class == proto.ClassSafe:
			t.Errorf("--%s admits %s (0x%02x), which is already ClassSafe and needs no flag",
				u.flag, u.op.Name(), byte(u.op))
		case class >= proto.ClassDestructive:
			t.Errorf("--%s admits a destructive opcode (0x%02x); the transport would refuse it anyway, "+
				"but it must not be offered", u.flag, byte(u.op))
		}
	}
}

// TestUnlockFlagNamesMatchTheirOpcode keeps --allow-90 from being wired to 0x98.
// The flags are generated from this table, so the name is the only thing tying a
// flag to an opcode, and a transposition would be invisible.
func TestUnlockFlagNamesMatchTheirOpcode(t *testing.T) {
	seen := map[string]bool{}
	for _, u := range unlockable {
		want := fmt.Sprintf("allow-%02x", byte(u.op))
		if u.flag != want {
			t.Errorf("opcode 0x%02x has flag --%s, want --%s", byte(u.op), u.flag, want)
		}
		if seen[u.flag] {
			t.Errorf("--%s is listed twice", u.flag)
		}
		seen[u.flag] = true
		if u.help == "" {
			t.Errorf("--%s has no help text; the reason a frame is safe enough to try is the point of the flag", u.flag)
		}
	}
}

// TestParseStepsNeedsTheFlagForEveryNewOpcode covers the Phase 5a frames the
// same way Run 10's were covered: named in --steps without its flag, a
// state-changing opcode is refused before the device is opened, and the refusal
// names the flag to use.
func TestParseStepsNeedsTheFlagForEveryNewOpcode(t *testing.T) {
	for _, u := range unlockable {
		hex := fmt.Sprintf("%02x", byte(u.op))
		t.Run(hex, func(t *testing.T) {
			_, err := parseSteps(hex)
			if err == nil {
				t.Fatalf("--steps %s was accepted with no --%s", hex, u.flag)
			}
			if !strings.Contains(err.Error(), "--"+u.flag) {
				t.Errorf("refusal %q does not name --%s", err, u.flag)
			}

			ops, err := parseSteps(hex, u.op)
			if fdtArm(u.op) {
				// The finger-detect arms have no fixed payload, so the flag
				// admits them to --wait-finger and never to --steps.
				if err == nil || !strings.Contains(err.Error(), "--wait-finger") {
					t.Fatalf("--steps %s with the flag set = %v, want a refusal naming --wait-finger", hex, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("--steps %s with the flag set = %v", hex, err)
			}
			if len(ops) != 1 || ops[0] != u.op {
				t.Fatalf("parseSteps(%q) = %v, want [0x%02x]", hex, ops, byte(u.op))
			}
		})
	}
}

// TestTLSConfigValidate covers the flag combinations. Every one of these is
// checked before the device is opened, so a mistake costs a message rather than
// a live run against the part that killed the keyboard.
func TestTLSConfigValidate(t *testing.T) {
	allowD0 := map[proto.Opcode]bool{opRequestTLS: true}
	allowD0And20 := map[proto.Opcode]bool{opRequestTLS: true, opGetImage: true}

	cases := []struct {
		name    string
		cfg     tlsConfig
		steps   []proto.Opcode
		allowed map[proto.Opcode]bool
		wantErr string // a substring, or "" for success
	}{
		{
			name:    "off, and no stray flags",
			cfg:     tlsConfig{},
			allowed: nil,
		},
		{
			name:    "--psk without --tls",
			cfg:     tlsConfig{pskPath: "captures/goodix-psk.bin"},
			wantErr: "only mean something with --tls",
		},
		{
			name:    "--tls without --psk",
			cfg:     tlsConfig{enabled: true},
			allowed: allowD0,
			wantErr: "needs --psk",
		},
		{
			name:    "--tls without --allow-d0",
			cfg:     tlsConfig{enabled: true, pskPath: "k.bin"},
			allowed: nil,
			wantErr: "--allow-d0",
		},
		{
			name:    "d0 also named in --steps",
			cfg:     tlsConfig{enabled: true, pskPath: "k.bin"},
			steps:   []proto.Opcode{0xa8, opRequestTLS},
			allowed: allowD0,
			wantErr: "sends 0xd0 itself",
		},
		{
			name:    "--capture without --allow-20",
			cfg:     tlsConfig{enabled: true, pskPath: "k.bin", capture: "captures/frame.pgm"},
			allowed: allowD0,
			wantErr: "--allow-20",
		},
		{
			name:    "handshake only",
			cfg:     tlsConfig{enabled: true, pskPath: "k.bin"},
			steps:   []proto.Opcode{0xa8, 0xae},
			allowed: allowD0,
		},
		{
			name:    "--wait-finger without --capture",
			cfg:     tlsConfig{enabled: true, pskPath: "k.bin", waitFinger: true, armDown: true, armUp: true, fingerTimeout: time.Second},
			allowed: allowD0,
			wantErr: "needs --capture",
		},
		{
			name: "--wait-finger without --allow-34",
			cfg: tlsConfig{enabled: true, pskPath: "k.bin", capture: "captures/frame.pgm", getImage: true,
				waitFinger: true, armDown: true, fingerTimeout: time.Second},
			allowed: allowD0And20,
			wantErr: "--allow-34",
		},
		{
			name:    "--wait-finger without --tls",
			cfg:     tlsConfig{waitFinger: true},
			wantErr: "only mean something with --tls",
		},
		{
			name: "capture on touch",
			cfg: tlsConfig{enabled: true, pskPath: "k.bin", capture: "captures/frame.pgm", getImage: true,
				waitFinger: true, armDown: true, armUp: true, fingerTimeout: time.Second},
			allowed: allowD0And20,
		},
		{
			name:    "handshake and capture",
			cfg:     tlsConfig{enabled: true, pskPath: "k.bin", capture: "captures/frame.pgm", getImage: true},
			allowed: allowD0And20,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate(tc.steps, tc.allowed)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("validate = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("validate = nil, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("validate = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestTLSOpcodesAreCataloguedAndUnlocked: the bridge sends commands that are not
// --steps entries, so they bypass parseSteps. They must still be frames the
// vendor sends, and each must still be behind its own flag.
func TestTLSOpcodesAreCataloguedAndUnlocked(t *testing.T) {
	cfg := tlsConfig{enabled: true, sendD4: true, getImage: true}
	ops := cfg.opcodes()
	if len(ops) != 3 {
		t.Fatalf("a fully unlocked --tls run sends %d commands, want 3 (0xd0, 0xd4, 0x20)", len(ops))
	}
	for _, op := range ops {
		if _, ok := stepFor(op); !ok {
			t.Errorf("the bridge sends 0x%02x, which has no catalogue entry and so no vendor payload", byte(op))
		}
		if _, ok := unlockFor(op); !ok {
			t.Errorf("the bridge sends 0x%02x, which has no --allow-… flag", byte(op))
		}
	}

	// Without the flags, the bridge asks for less: an operator who unlocked only
	// 0xd0 gets the handshake and nothing after it.
	if got := (tlsConfig{enabled: true}).opcodes(); len(got) != 1 || got[0] != opRequestTLS {
		t.Errorf("a --tls run with only --allow-d0 sends %v, want just 0xd0", got)
	}
	if got := (tlsConfig{}).opcodes(); got != nil {
		t.Errorf("a run without --tls sends %v, want nothing", got)
	}
}

// TestSyntheticFrameMatchesTheSensor keeps the rehearsal honest about geometry:
// the stand-in's frame must be exactly what 64 x 80 packed 12-bit samples
// occupy, or the rehearsal would exercise TrimFrame's error path instead of its
// success path.
func TestSyntheticFrameMatchesTheSensor(t *testing.T) {
	frame, err := syntheticFrame()
	if err != nil {
		t.Fatalf("syntheticFrame: %v", err)
	}
	want, err := image.PackedLen(sensorWidth, sensorHeight)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != want {
		t.Fatalf("syntheticFrame is %d bytes, want %d", len(frame), want)
	}

	trimmed, layout, err := image.TrimFrame(frame, sensorWidth, sensorHeight)
	if err != nil {
		t.Fatalf("TrimFrame on the synthetic frame: %v", err)
	}
	if layout != image.LayoutBare {
		t.Errorf("layout = %v, want bare", layout)
	}
	if _, err := image.Decode12BitPacked(trimmed, sensorWidth, sensorHeight); err != nil {
		t.Errorf("decoding the synthetic frame: %v", err)
	}
}

// TestVendorInitBeforeTLS pins the vendor's pre-0xd0 order, which the stall
// diagnosis and the runbook's --tls command line are both read against. The
// driver log shows it in every init, 0xe4 included, ahead of every handshake
// that completed.
func TestVendorInitBeforeTLS(t *testing.T) {
	const want = "96,a8,ae,e4,a2,82,a6,a2,70,98,90"
	if got := opList(vendorBeforeTLS()); got != want {
		t.Fatalf("vendorBeforeTLS() = %s, want %s", got, want)
	}

	// The whole list has to be sendable as --steps, each above-ceiling opcode
	// behind its own flag, or the runbook's command line cannot be typed.
	var allow []proto.Opcode
	for _, u := range unlockable {
		allow = append(allow, u.op)
	}
	ops, err := parseSteps(want, allow...)
	if err != nil {
		t.Fatalf("parseSteps(%q) with every unlock flag = %v", want, err)
	}
	if missing := missingFromVendorInit(ops); len(missing) != 0 {
		t.Errorf("the vendor's own init is missing %s from itself", opList(missing))
	}
}

// TestMissingFromVendorInitNamesRun11sGap checks the diagnosis on the run that
// needed it: Run 11 sent the vendor's init without 0xe4, and stalled.
func TestMissingFromVendorInitNamesRun11sGap(t *testing.T) {
	var allow []proto.Opcode
	for _, u := range unlockable {
		allow = append(allow, u.op)
	}
	run11, err := parseSteps("96,a8,ae,a2,82,a6,a2,70,98,90", allow...)
	if err != nil {
		t.Fatalf("parseSteps: %v", err)
	}
	if got := opList(missingFromVendorInit(run11)); got != "e4" {
		t.Errorf("missingFromVendorInit(Run 11) = %q, want \"e4\"", got)
	}
}
