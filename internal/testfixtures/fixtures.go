// Package testfixtures is imported only by tests. Expected protocol bytes are
// embedded literal data, never produced by a Go or C protocol implementation.
package testfixtures

import (
	"bufio"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata/protocol.ini
var protocolData []byte

type Section struct {
	Name   string
	Values map[string]string
}
type Corpus []Section

func Parse(data []byte) (Corpus, error) {
	var c Corpus
	seen := map[string]bool{}
	scan := bufio.NewScanner(strings.NewReader(string(data)))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := line[1 : len(line)-1]
			if seen[name] {
				return nil, fmt.Errorf("duplicate section %s", name)
			}
			seen[name] = true
			c = append(c, Section{Name: name, Values: map[string]string{}})
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || len(c) == 0 {
			return nil, fmt.Errorf("invalid corpus line %q", line)
		}
		k = strings.TrimSpace(k)
		if _, ok := c[len(c)-1].Values[k]; ok {
			return nil, fmt.Errorf("duplicate key %s", k)
		}
		c[len(c)-1].Values[k] = strings.TrimSpace(v)
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	if len(c) == 0 {
		return nil, fmt.Errorf("empty corpus")
	}
	for _, s := range c {
		if err := validate(s); err != nil {
			return nil, fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	return c, nil
}

func Load(t testing.TB) Corpus {
	t.Helper()
	c, err := Parse(protocolData)
	if err != nil {
		t.Fatal(err)
	}
	for prefix, n := range map[string]int{"init.": 14, "health": 1, "loop.": 3, "arm.": 3, "event.": 10, "pair.": 21, "image": 1} {
		if len(c.Prefix(prefix)) != n {
			t.Fatalf("incomplete %s inventory", prefix)
		}
	}
	return c
}
func (c Corpus) Prefix(prefix string) Corpus {
	var out Corpus
	for _, s := range c {
		if strings.HasPrefix(s.Name, prefix) {
			out = append(out, s)
		}
	}
	return out
}
func (c Corpus) Section(t testing.TB, name string) Section {
	t.Helper()
	for _, s := range c {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("missing fixture section %s", name)
	return Section{}
}
func (s Section) String(t testing.TB, key string) string {
	t.Helper()
	v, ok := s.Values[key]
	if !ok {
		t.Fatalf("%s: missing %s", s.Name, key)
	}
	return v
}
func (s Section) Hex(t testing.TB, key string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s.String(t, key))
	if err != nil {
		t.Fatalf("%s/%s: %v", s.Name, key, err)
	}
	return b
}
func (s Section) Int(t testing.TB, key string) int {
	t.Helper()
	n, err := strconv.Atoi(s.String(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func (s Section) Ints(t testing.TB, key string) []int {
	t.Helper()
	var out []int
	for _, v := range strings.Split(strings.TrimSuffix(s.String(t, key), ";"), ";") {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// The deliberately small format is shared with the GLib reader. Hex is
// contiguous, numbers are nonnegative decimal, and lists end in semicolons.
func validate(s Section) error {
	var spec string
	switch {
	case strings.HasPrefix(s.Name, "init."), s.Name == "health", strings.HasPrefix(s.Name, "loop."):
		spec = "cmd:h payload:h reply:r data:h secret:n"
	case strings.HasPrefix(s.Name, "arm."):
		spec = "cmd:h thresholds:h timestamp:n payload:h"
	case strings.HasPrefix(s.Name, "event."):
		spec = "cmd:h payload:h kind:n zones:l"
	case strings.HasPrefix(s.Name, "pair."):
		spec = "cmd:h event:h kind:n zones:l arm_cmd:h delta:n timestamp:n thresholds:h payload:h"
	case s.Name == "image":
		spec = "width:n height:n packed_len:n wrapped_len:n header:h trailer:h pattern:h samples:l gray:h repetitions:n rejected_lengths:l"
	default:
		return fmt.Errorf("unknown section")
	}
	fields := strings.Fields(spec)
	if len(s.Values) != len(fields) {
		return fmt.Errorf("incomplete or unknown fields")
	}
	for _, field := range fields {
		key, typ, _ := strings.Cut(field, ":")
		value, ok := s.Values[key]
		if !ok {
			return fmt.Errorf("missing %s", key)
		}
		switch typ {
		case "h":
			b, err := hex.DecodeString(value)
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			if key != "data" && len(b) == 0 {
				return fmt.Errorf("empty %s", key)
			}
			if (key == "cmd" || key == "arm_cmd") && len(b) != 1 {
				return fmt.Errorf("bad command")
			}
			if key == "thresholds" && len(b) != 6 {
				return fmt.Errorf("need six thresholds")
			}
		case "n", "l":
			vs := []string{value}
			if typ == "l" {
				if !strings.HasSuffix(value, ";") {
					return fmt.Errorf("list must end in semicolon")
				}
				vs = strings.Split(strings.TrimSuffix(value, ";"), ";")
			}
			if key == "zones" && len(vs) != 6 {
				return fmt.Errorf("need six zones")
			}
			for _, v := range vs {
				for _, r := range v {
					if r < '0' || r > '9' {
						return fmt.Errorf("invalid %s", key)
					}
				}
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 || n > 65535 {
					return fmt.Errorf("invalid %s", key)
				}
				if key == "secret" && n > 1 || key == "kind" && n > 4 || key == "delta" && n > 255 {
					return fmt.Errorf("invalid %s", key)
				}
			}
		case "r":
			switch value {
			case "none", "ack", "data", "ack-data", "tls", "ack-tls":
			default:
				return fmt.Errorf("invalid reply mode")
			}
		}
	}
	return nil
}
