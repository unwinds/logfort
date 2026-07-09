//go:build linux

package netwatch

import (
	"os"
	"sort"
)

// PortsAvailable reports whether listening-port enumeration works here.
const PortsAvailable = true

// ListeningPorts returns the sorted set of TCP ports in LISTEN state across
// IPv4 and IPv6 (from /proc/net/tcp and /proc/net/tcp6).
func ListeningPorts() ([]int, error) {
	seen := map[int]struct{}{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. IPv6 disabled
			}
			return nil, err
		}
		for _, p := range parseProcNetTCP(string(data)) {
			seen[p] = struct{}{}
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}
