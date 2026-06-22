package responder

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/unwinds/sshwatch/internal/config"
)

// Responder manages active banning of IP addresses.
type Responder interface {
	Ban(ctx context.Context, ip string) error
	Unban(ctx context.Context, ip string) error
	List(ctx context.Context) ([]string, error)
	Name() string
}

// New returns a Responder and parsed Allowlist from config.
// If responder is disabled, returns NoopResponder.
func New(cfg *config.Config) (Responder, *Allowlist, error) {
	al, err := ParseAllowlist(cfg.IgnoreIPs)
	if err != nil {
		return nil, nil, fmt.Errorf("allowlist: %w", err)
	}
	if !cfg.ResponderEnabled {
		return NoopResponder{}, al, nil
	}
	switch cfg.ResponderBackend {
	case "nftables":
		r, err := newNftablesResponder(cfg.NftTable, cfg.NftSet)
		if err != nil {
			return nil, nil, fmt.Errorf("nftables responder: %w", err)
		}
		return r, al, nil
	case "fail2ban":
		return newFail2BanResponder("sshd"), al, nil
	default:
		return nil, nil, fmt.Errorf("unknown responder backend %q; use nftables or fail2ban", cfg.ResponderBackend)
	}
}

// Allowlist holds CIDRs and individual IPs that must never be banned.
type Allowlist struct {
	nets []*net.IPNet
	ips  []net.IP
}

// ParseAllowlist parses CIDR ranges and individual IP addresses.
func ParseAllowlist(entries []string) (*Allowlist, error) {
	al := &Allowlist{}
	for _, e := range entries {
		if _, ipNet, err := net.ParseCIDR(e); err == nil {
			al.nets = append(al.nets, ipNet)
		} else if ip := net.ParseIP(e); ip != nil {
			al.ips = append(al.ips, ip)
		} else {
			return nil, fmt.Errorf("invalid IP or CIDR: %q", e)
		}
	}
	return al, nil
}

// Contains reports whether the given IP string is in the allowlist.
func (al *Allowlist) Contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range al.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, a := range al.ips {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

// IsPrivate reports whether the IP is loopback, link-local, or RFC-1918 private.
func IsPrivate(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// IsValid reports whether ipStr is a syntactically valid IP address.
func IsValid(ipStr string) bool {
	_, err := netip.ParseAddr(ipStr)
	return err == nil
}
