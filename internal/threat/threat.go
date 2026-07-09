// Package threat provides a local, offline IP blocklist. A file of IPs and
// CIDR ranges (one per line, "#" comments allowed) is loaded once at startup
// and consulted for every event's source IP — no outbound calls, mirroring the
// GeoIP/ASN mmdb pattern. A match enriches the event and can optionally trigger
// an immediate ban.
package threat

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// maxEntries caps how many blocklist lines are loaded, guarding against an
// accidentally huge or malicious file exhausting memory.
const maxEntries = 5_000_000

// List is an immutable set of blocked IPs and prefixes. The zero value and a
// nil *List are safe: Lookup returns "" (not listed).
//
// Prefixes are stored in a set keyed by the masked netip.Prefix and indexed by
// the distinct prefix lengths present (separately per address family). Lookup
// masks the query address to each present length and probes the set — O(number
// of distinct prefix lengths), a small constant — instead of scanning every
// CIDR, which matters on the per-event ingest hot path for large blocklists.
type List struct {
	name string
	ips  map[netip.Addr]struct{}

	prefixes    map[netip.Prefix]struct{}
	prefixLens4 []int // distinct IPv4 prefix lengths present (ascending, ≤32)
	prefixLens6 []int // distinct IPv6 prefix lengths present (ascending, ≤128)
}

// Name returns the human-readable list name (derived from the file name).
func (l *List) Name() string {
	if l == nil {
		return ""
	}
	return l.name
}

// Count returns the number of loaded entries (individual IPs + prefixes).
func (l *List) Count() int {
	if l == nil {
		return 0
	}
	return len(l.ips) + len(l.prefixes)
}

// Lookup reports the list name if ipStr is blocked, or "" otherwise.
// A nil list, an empty list, or an unparseable IP all return "".
func (l *List) Lookup(ipStr string) string {
	if l == nil || (len(l.ips) == 0 && len(l.prefixes) == 0) {
		return ""
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ""
	}
	addr = addr.Unmap() // treat ::ffff:1.2.3.4 as 1.2.3.4
	if _, ok := l.ips[addr]; ok {
		return l.name
	}
	lens := l.prefixLens4
	if !addr.Is4() {
		lens = l.prefixLens6
	}
	for _, bits := range lens {
		// addr.Prefix masks the host bits, yielding the network that would
		// contain addr at this length; a set hit means addr is inside it.
		p, err := addr.Prefix(bits)
		if err != nil {
			continue // bits > addr.BitLen(); cannot happen given per-family lens
		}
		if _, ok := l.prefixes[p]; ok {
			return l.name
		}
	}
	return ""
}

// Open loads a blocklist file. The list name is the file's base name without
// extension. Malformed lines are skipped (a blocklist with a few bad rows must
// still load); a completely unreadable file returns an error.
func Open(path string) (*List, error) {
	f, err := os.Open(path) // #nosec G304 -- admin-provided path, same trust as the mmdb files
	if err != nil {
		return nil, fmt.Errorf("open blocklist %q: %w", path, err)
	}
	defer f.Close()
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return parse(name, f)
}

// parse builds a List from a reader. Exported behaviour is tested through here.
func parse(name string, r io.Reader) (*List, error) {
	l := &List{
		name:     name,
		ips:      make(map[netip.Addr]struct{}),
		prefixes: make(map[netip.Prefix]struct{}),
	}
	var have4 [33]bool  // IPv4 prefix lengths seen (0..32)
	var have6 [129]bool // IPv6 prefix lengths seen (0..128)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		if n >= maxEntries {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Some feeds append a comment or count after the entry ("1.2.3.4 ; foo").
		if i := strings.IndexAny(line, " \t;#"); i >= 0 {
			line = line[:i]
		}
		if line == "" {
			continue
		}
		if strings.ContainsRune(line, '/') {
			if p, err := netip.ParsePrefix(line); err == nil {
				p = p.Masked()
				if _, dup := l.prefixes[p]; !dup {
					l.prefixes[p] = struct{}{}
					if p.Addr().Is4() {
						have4[p.Bits()] = true
					} else {
						have6[p.Bits()] = true
					}
				}
				n++
			}
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			l.ips[a.Unmap()] = struct{}{}
			n++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read blocklist: %w", err)
	}
	for b := 0; b <= 32; b++ {
		if have4[b] {
			l.prefixLens4 = append(l.prefixLens4, b)
		}
	}
	for b := 0; b <= 128; b++ {
		if have6[b] {
			l.prefixLens6 = append(l.prefixLens6, b)
		}
	}
	return l, nil
}
