//go:build !linux

package netwatch

import "errors"

// PortsAvailable reports whether listening-port enumeration works here.
const PortsAvailable = false

// ListeningPorts is unsupported off Linux.
func ListeningPorts() ([]int, error) {
	return nil, errors.New("netwatch: listening-port enumeration unavailable on this platform")
}
