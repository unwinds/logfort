package responder

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/unwinds/logfort/internal/config"
)

// Responder manages active banning of IP addresses.
type Responder interface {
	Ban(ctx context.Context, ip string) error
	Unban(ctx context.Context, ip string) error
	List(ctx context.Context) ([]string, error)
	Name() string
}

// New returns a Responder and parsed Allowlist from config.
// If responder is disabled, returns NoopResponder. ParseAllowlist errors are
// only fatal when the responder is enabled — a misconfigured IGNORE_IPS must
// not break startup for users who never enable active banning.
func New(cfg *config.Config) (Responder, *Allowlist, error) {
	al, allowlistErr := ParseAllowlist(cfg.IgnoreIPs)
	if allowlistErr != nil {
		if cfg.ResponderEnabled {
			return nil, nil, fmt.Errorf("allowlist: %w", allowlistErr)
		}
		// Allowlist is still used for API validation; fall back to empty.
		al = &Allowlist{}
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
		return newFail2BanResponder(cfg.Fail2BanSocket, cfg.Fail2BanJail), al, nil
	default:
		return nil, nil, fmt.Errorf("unknown responder backend %q; use nftables or fail2ban", cfg.ResponderBackend)
	}
}

// Allowlist holds CIDRs and individual IPs that must never be banned.
// The base set comes from LOGFORT_IGNORE_IPS at startup and is immutable;
// extra entries can be swapped at runtime from the settings UI. All methods
// are safe for concurrent use.
type Allowlist struct {
	nets []*net.IPNet
	ips  []net.IP

	mu        sync.RWMutex
	extraNets []*net.IPNet
	extraIPs  []net.IP
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

// SetExtra replaces the runtime-added allowlist entries (settings UI).
// Invalid entries return an error and leave the previous extra set intact.
func (al *Allowlist) SetExtra(entries []string) error {
	parsed, err := ParseAllowlist(entries)
	if err != nil {
		return err
	}
	al.mu.Lock()
	al.extraNets, al.extraIPs = parsed.nets, parsed.ips
	al.mu.Unlock()
	return nil
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
	al.mu.RLock()
	defer al.mu.RUnlock()
	for _, n := range al.extraNets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, a := range al.extraIPs {
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
