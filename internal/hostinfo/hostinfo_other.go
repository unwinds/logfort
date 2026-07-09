//go:build !linux

package hostinfo

import "errors"

const procAvailable = false

var errUnsupported = errors.New("hostinfo: host vitals unavailable on this platform")

func numCPU() int { return 0 }

func readCPU() (uint64, uint64, error)             { return 0, 0, errUnsupported }
func readMem() (uint64, uint64, error)             { return 0, 0, errUnsupported }
func readLoad() (float64, float64, float64, error) { return 0, 0, 0, errUnsupported }
func readUptime() (int64, error)                   { return 0, errUnsupported }
func readDisk(string) (uint64, uint64, error)      { return 0, 0, errUnsupported }
