package testfixtures

import (
	"strings"
	"testing"
)

// A permissive reader could silently replace an independent reference with a
// later duplicate, or skip malformed hex and leave a parity test empty.
func TestParseRejectsBrokenCorpus(t *testing.T) {
	for name, input := range map[string]string{
		"empty":             "",
		"missing_section":   "cmd=a8\n",
		"duplicate_section": "[health]\ncmd=a8\n[health]\ncmd=a8\n",
		"duplicate_key":     "[health]\ncmd=a8\ncmd=96\n",
		"malformed_line":    "[health]\ncmd\n",
		"missing_fields":    "[health]\ncmd=a8\n",
		"odd_hex":           "[arm.down]\ncmd=32\nthresholds=123\ntimestamp=0\npayload=00\n",
		"bad_hex":           "[arm.down]\ncmd=32\nthresholds=zz\ntimestamp=0\npayload=00\n",
		"bad_integer":       "[arm.down]\ncmd=32\nthresholds=010203040506\ntimestamp=oops\npayload=00\n",
		"unknown_section":   "[unknown]\nx=1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("accepted broken corpus")
			}
		})
	}
}

func TestLoadIndependentCorpus(t *testing.T) {
	c := Load(t)
	if len(c.Prefix("init.")) != 14 {
		t.Fatal("need all 14 init steps")
	}
	if c.Section(t, "init.10").Int(t, "secret") != 0 {
		t.Fatal("config must not be secret")
	}
	if len(c.Section(t, "init.10").Hex(t, "payload")) != 224 {
		t.Fatal("config must contain all 224 bytes")
	}
}

func TestParseRejectsIncompleteAndDuplicateReference(t *testing.T) {
	for _, old := range []string{"payload=0000\n", "thresholds=b8c5abb9aab9\n"} {
		raw := strings.Replace(string(protocolData), old, "", 1)
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("accepted missing %s", old)
		}
	}
	raw := string(protocolData) + "\n[health]\ncmd=a8\n"
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("accepted duplicate health")
	}
}
