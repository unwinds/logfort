//go:build !linux

package responder

import "fmt"

func newNftablesResponder(_, _ string) (Responder, error) {
	return nil, fmt.Errorf("nftables backend is only supported on Linux")
}
