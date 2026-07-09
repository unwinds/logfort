package hostinfo

import "testing"

func TestParseCPUStat(t *testing.T) {
	// user nice system idle iowait irq softirq steal
	total, idle, ok := parseCPUStat("cpu  100 0 50 800 40 0 10 0")
	if !ok {
		t.Fatal("expected ok")
	}
	if total != 1000 {
		t.Errorf("total: got %d, want 1000", total)
	}
	if idle != 840 { // idle 800 + iowait 40
		t.Errorf("idle: got %d, want 840", idle)
	}
	if _, _, ok := parseCPUStat("cpu0 1 2 3"); ok {
		t.Error("per-core / short line should not parse as aggregate")
	}
	if _, _, ok := parseCPUStat("intr 1 2 3 4 5"); ok {
		t.Error("non-cpu line should not parse")
	}
}

func TestParseMemInfo(t *testing.T) {
	data := "MemTotal:       16384000 kB\nMemFree:  1000000 kB\nMemAvailable:    8192000 kB\n"
	total, avail, ok := parseMemInfo(data)
	if !ok {
		t.Fatal("expected ok")
	}
	if total != 16384000*1024 {
		t.Errorf("total: got %d", total)
	}
	if avail != 8192000*1024 {
		t.Errorf("available: got %d", avail)
	}
	if _, _, ok := parseMemInfo("MemFree: 100 kB\n"); ok {
		t.Error("missing MemTotal/MemAvailable should not parse")
	}
}

func TestParseLoadAvg(t *testing.T) {
	l1, l5, l15, ok := parseLoadAvg("0.52 0.31 0.15 2/431 98765")
	if !ok {
		t.Fatal("expected ok")
	}
	if l1 != 0.52 || l5 != 0.31 || l15 != 0.15 {
		t.Errorf("got %v %v %v", l1, l5, l15)
	}
	if _, _, _, ok := parseLoadAvg("0.1 0.2"); ok {
		t.Error("short loadavg should not parse")
	}
}

func TestParseUptime(t *testing.T) {
	v, ok := parseUptime("12345.67 6789.01")
	if !ok || v != 12345 {
		t.Errorf("got %d ok=%v, want 12345", v, ok)
	}
}

func TestRound1(t *testing.T) {
	if got := round1(12.34); got != 12.3 {
		t.Errorf("round1(12.34): got %v", got)
	}
	if got := round1(99.95); got != 100 {
		t.Errorf("round1(99.95): got %v", got)
	}
}
