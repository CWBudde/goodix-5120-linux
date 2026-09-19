package main

import (
	"strings"
	"testing"
)

// fakeReads turns a list of samples into an ecRefreshCounter read function.
// After the list is exhausted the last value repeats, which is what a frozen EC
// looks like.
func fakeReads(samples ...string) func() (string, bool) {
	i := 0
	return func() (string, bool) {
		if len(samples) == 0 {
			return "", false
		}
		v := samples[i]
		if i < len(samples)-1 {
			i++
		}
		return v, true
	}
}

func TestECRefreshCounterCountsChanges(t *testing.T) {
	c := &ecRefreshCounter{read: fakeReads("a", "a", "b", "b", "c")}
	for range 5 {
		c.sample()
	}
	n, ok := c.count()
	if !ok {
		t.Fatal("count reported nothing readable, want readable")
	}
	if n != 2 { // a->b and b->c
		t.Errorf("changes = %d, want 2", n)
	}
}

// The first sample establishes the baseline. Counting it would make a machine
// that never updates look alive on its first check.
func TestECRefreshCounterDoesNotCountTheBaseline(t *testing.T) {
	c := &ecRefreshCounter{read: fakeReads("a")}
	c.sample()
	if n, _ := c.count(); n != 0 {
		t.Errorf("changes after one sample = %d, want 0", n)
	}
}

// A frozen EC is the case this whole counter exists for: readable, unchanging.
func TestECRefreshCounterStandsStillWhenTheValuesFreeze(t *testing.T) {
	c := &ecRefreshCounter{read: fakeReads("a", "b")}
	c.sample()
	c.sample() // a -> b
	before, _ := c.count()
	for range 30 {
		c.sample()
	}
	after, _ := c.count()
	if after != before {
		t.Errorf("changes moved from %d to %d while the values were frozen", before, after)
	}
}

// No battery, or a sysfs we cannot read, must not look like a dead EC. It has to
// be distinguishable, which is what the second return value is for.
func TestECRefreshCounterSeparatesUnreadableFromUnchanged(t *testing.T) {
	c := &ecRefreshCounter{read: func() (string, bool) { return "", false }}
	for range 5 {
		c.sample()
	}
	if _, ok := c.count(); ok {
		t.Error("count reported readable, want unreadable")
	}
}

// The SCI count was logged for four live runs and meant nothing in any of them
// (docs/acpi.md). It must not creep back in.
func TestSnapshotReportsTheECAndNotTheSCICount(t *testing.T) {
	h := &linuxHost{ec: &ecRefreshCounter{read: fakeReads("a", "b")}}
	h.ec.sample()
	h.ec.sample()

	got := h.Snapshot()
	if !strings.Contains(got, "ec refreshes=1") {
		t.Errorf("Snapshot() = %q, want it to report ec refreshes=1", got)
	}
	if strings.Contains(strings.ToLower(got), "sci") {
		t.Errorf("Snapshot() = %q, want no SCI count", got)
	}
}

func TestSnapshotSaysSoWhenThereIsNoBattery(t *testing.T) {
	h := &linuxHost{ec: &ecRefreshCounter{read: func() (string, bool) { return "", false }}}
	if got := h.Snapshot(); !strings.Contains(got, "ec refreshes=?") {
		t.Errorf("Snapshot() = %q, want it to flag the EC counter as unavailable", got)
	}
}

// readBatteryTuple touches the real machine, so it only asserts the shape.
func TestReadBatteryTupleReadsThisMachine(t *testing.T) {
	v, ok := readBatteryTuple()
	if !ok {
		t.Skip("no battery on this machine")
	}
	if strings.TrimSpace(v) == "" {
		t.Error("readBatteryTuple reported readable but returned nothing")
	}
}
