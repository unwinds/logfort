// Package hostinfo samples lightweight host vitals — CPU, memory, load, disk —
// from the local kernel (Linux /proc + statfs, no external dependencies). It is
// deliberately thin: LogFort is a security monitor with a health readout, not a
// metrics platform. On non-Linux builds every reader is a stub so the rest of
// the code compiles and tests run anywhere.
package hostinfo

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshot is an instantaneous view of host vitals. All percentages are 0–100.
type Snapshot struct {
	Available       bool    `json:"available"`
	CPUPercent      float64 `json:"cpu_percent"`
	NumCPU          int     `json:"num_cpu"`
	MemTotal        uint64  `json:"mem_total"`
	MemUsed         uint64  `json:"mem_used"`
	MemUsedPercent  float64 `json:"mem_used_percent"`
	Load1           float64 `json:"load1"`
	Load5           float64 `json:"load5"`
	Load15          float64 `json:"load15"`
	DiskPath        string  `json:"disk_path"`
	DiskTotal       uint64  `json:"disk_total"`
	DiskFree        uint64  `json:"disk_free"`
	DiskUsedPercent float64 `json:"disk_used_percent"`
	HostUptimeSecs  int64   `json:"host_uptime_s"`
}

// Sampler periodically refreshes a Snapshot in the background so that readers
// (the API and metrics) never block on file I/O and CPU% is measured over a
// real interval rather than a single instant.
type Sampler struct {
	diskPath string
	interval time.Duration

	mu   sync.RWMutex
	snap Snapshot

	// previous CPU counters for delta-based utilisation.
	prevTotal, prevIdle uint64
	havePrev            bool
}

// NewSampler returns a Sampler that reports disk usage for the filesystem
// holding diskPath.
func NewSampler(diskPath string) *Sampler {
	return &Sampler{diskPath: diskPath, interval: 5 * time.Second}
}

// Available reports whether host vitals can be read on this platform.
func (s *Sampler) Available() bool { return procAvailable }

// Snapshot returns the most recent vitals reading.
func (s *Sampler) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// Start samples immediately and then every interval until ctx is cancelled.
// A no-op on platforms without /proc.
func (s *Sampler) Start(ctx context.Context) {
	if !procAvailable {
		return
	}
	s.sample()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sample()
		}
	}
}

func (s *Sampler) sample() {
	snap := Snapshot{Available: true, DiskPath: s.diskPath}

	if total, idle, err := readCPU(); err == nil {
		if s.havePrev && total > s.prevTotal {
			dt := total - s.prevTotal
			di := idle - s.prevIdle
			if di <= dt {
				snap.CPUPercent = round1(100 * float64(dt-di) / float64(dt))
			}
		}
		s.prevTotal, s.prevIdle, s.havePrev = total, idle, true
	}
	snap.NumCPU = numCPU()

	if memTotal, memAvail, err := readMem(); err == nil && memTotal > 0 {
		used := memTotal - memAvail
		snap.MemTotal, snap.MemUsed = memTotal, used
		snap.MemUsedPercent = round1(100 * float64(used) / float64(memTotal))
	}

	if l1, l5, l15, err := readLoad(); err == nil {
		snap.Load1, snap.Load5, snap.Load15 = l1, l5, l15
	}

	if up, err := readUptime(); err == nil {
		snap.HostUptimeSecs = up
	}

	if dTotal, dFree, err := readDisk(s.diskPath); err == nil && dTotal > 0 {
		snap.DiskTotal, snap.DiskFree = dTotal, dFree
		snap.DiskUsedPercent = round1(100 * float64(dTotal-dFree) / float64(dTotal))
	}

	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}

// --- pure parsers (unit-tested; used by the platform readers) ---

// parseCPUStat parses the aggregate "cpu ..." line of /proc/stat into total and
// idle jiffies. idle includes iowait, matching how utilities compute busy time.
func parseCPUStat(line string) (total, idle uint64, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += v
		if i == 3 || i == 4 { // idle (index 3) + iowait (index 4)
			idle += v
		}
	}
	return total, idle, true
}

// parseMemInfo extracts MemTotal and MemAvailable (bytes) from /proc/meminfo.
func parseMemInfo(data string) (total, available uint64, ok bool) {
	var haveTotal, haveAvail bool
	for _, line := range strings.Split(data, "\n") {
		key, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch key {
		case "MemTotal":
			total, haveTotal = kbToBytes(rest)
		case "MemAvailable":
			available, haveAvail = kbToBytes(rest)
		}
	}
	return total, available, haveTotal && haveAvail
}

func kbToBytes(s string) (uint64, bool) {
	fields := strings.Fields(s) // "16384000 kB"
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return v * 1024, true
}

// parseLoadAvg parses the three load figures from /proc/loadavg.
func parseLoadAvg(s string) (l1, l5, l15 float64, ok bool) {
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	var err error
	if l1, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return 0, 0, 0, false
	}
	if l5, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return 0, 0, 0, false
	}
	if l15, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return 0, 0, 0, false
	}
	return l1, l5, l15, true
}

// parseUptime parses whole seconds from /proc/uptime.
func parseUptime(s string) (int64, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return int64(f), true
}
