// Package netwatch provides two lightweight, on-demand security probes:
// TLS certificate expiry for a configured set of endpoints, and the set of
// locally-listening TCP ports (a new one appearing can mean a backdoor). Both
// stay local except the deliberate outbound TLS handshake used to read a
// server's own certificate.
package netwatch

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CertStatus is the result of one certificate-expiry probe.
type CertStatus struct {
	Target    string `json:"target"`
	ExpiresAt int64  `json:"expires_at,omitempty"` // Unix seconds; 0 on error
	DaysLeft  int    `json:"days_left"`
	Error     string `json:"error,omitempty"`
}

// CheckCert connects to target (a "host" or "host:port"; port defaults to 443),
// completes a TLS handshake, and reports the leaf certificate's expiry. The
// certificate chain is intentionally not verified — the goal is to read the
// expiry date even for self-signed or already-expired certs, not to establish
// trust.
func CheckCert(ctx context.Context, target string) CertStatus {
	cs := CertStatus{Target: target}
	host := target
	hostOnly := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		hostOnly = h
	} else {
		host = net.JoinHostPort(target, "443")
	}

	dialer := &tls.Dialer{Config: &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- expiry audit, trust is not the goal
		ServerName:         hostOnly,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		cs.Error = err.Error()
		return cs
	}
	defer conn.Close()

	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		cs.Error = "no certificate presented"
		return cs
	}
	leaf := certs[0]
	cs.ExpiresAt = leaf.NotAfter.Unix()
	cs.DaysLeft = int(time.Until(leaf.NotAfter).Truncate(time.Hour).Hours() / 24)
	return cs
}

// parseProcNetTCP extracts the local listening ports from the contents of a
// /proc/net/tcp or /proc/net/tcp6 file. Rows in state 0A (TCP_LISTEN) are
// collected; the local port is the hex value after the ':' in column 2.
func parseProcNetTCP(data string) []int {
	seen := map[int]struct{}{}
	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		local := fields[1] // "0100007F:1F90"
		colon := strings.LastIndexByte(local, ':')
		if colon < 0 {
			continue
		}
		port, err := strconv.ParseUint(local[colon+1:], 16, 32)
		if err != nil {
			continue
		}
		seen[int(port)] = struct{}{}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
