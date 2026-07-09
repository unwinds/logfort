//go:build linux

package hostinfo

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

const procAvailable = true

var errParse = errors.New("hostinfo: could not parse")

func numCPU() int { return runtime.NumCPU() }

func readCPU() (total, idle uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	// The aggregate line is the first line of /proc/stat.
	line := string(data)
	if i := indexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	t, id, ok := parseCPUStat(line)
	if !ok {
		return 0, 0, errParse
	}
	return t, id, nil
}

func readMem() (total, available uint64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	t, a, ok := parseMemInfo(string(data))
	if !ok {
		return 0, 0, errParse
	}
	return t, a, nil
}

func readLoad() (l1, l5, l15 float64, err error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	a, b, c, ok := parseLoadAvg(string(data))
	if !ok {
		return 0, 0, 0, errParse
	}
	return a, b, c, nil
}

func readUptime() (int64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	v, ok := parseUptime(string(data))
	if !ok {
		return 0, errParse
	}
	return v, nil
}

func readDisk(path string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	// Total capacity, and free space available to unprivileged processes
	// (Bavail excludes root-reserved blocks — the number that actually matters).
	return st.Blocks * bs, st.Bavail * bs, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
