package f2b

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// JailSettings holds the tunable parameters of a fail2ban jail. Zero values
// mean "not set / leave unchanged".
type JailSettings struct {
	MaxRetry     int64 // failed attempts before ban
	BanTimeSecs  int64 // ban duration in seconds
	FindTimeSecs int64 // window in which failures are counted
}

// Manager exposes high-level operations on one fail2ban jail.
type Manager struct {
	client *Client
	jail   string
}

// NewManager creates a Manager for the given socket path and jail name.
func NewManager(socketPath, jail string) *Manager {
	if jail == "" {
		jail = "sshd"
	}
	return &Manager{client: NewClient(socketPath), jail: jail}
}

// Jail returns the managed jail name.
func (m *Manager) Jail() string { return m.jail }

// Available reports whether fail2ban is reachable (socket or CLI present).
func (m *Manager) Available() bool { return m.client.Available() }

// Ping checks that the fail2ban server responds.
func (m *Manager) Ping(ctx context.Context) error {
	v, err := m.client.Exec(ctx, "ping")
	if err != nil {
		return err
	}
	if s := Stringify(v); !strings.Contains(strings.ToLower(s), "pong") {
		return fmt.Errorf("f2b: unexpected ping reply: %s", s)
	}
	return nil
}

// GetJail reads the jail's current maxretry / bantime / findtime.
func (m *Manager) GetJail(ctx context.Context) (JailSettings, error) {
	var s JailSettings
	var err error
	if s.MaxRetry, err = m.getInt(ctx, "maxretry"); err != nil {
		return s, err
	}
	if s.BanTimeSecs, err = m.getInt(ctx, "bantime"); err != nil {
		return s, err
	}
	if s.FindTimeSecs, err = m.getInt(ctx, "findtime"); err != nil {
		return s, err
	}
	return s, nil
}

// SetJail applies the non-zero fields of s to the running jail. These are
// runtime settings: they take effect immediately but do not survive a
// fail2ban restart, so callers should re-apply them periodically (logfort
// does this from a background loop driven by the settings table).
func (m *Manager) SetJail(ctx context.Context, s JailSettings) error {
	if s.MaxRetry > 0 {
		if err := m.setInt(ctx, "maxretry", s.MaxRetry); err != nil {
			return err
		}
	}
	if s.BanTimeSecs > 0 {
		if err := m.setInt(ctx, "bantime", s.BanTimeSecs); err != nil {
			return err
		}
	}
	if s.FindTimeSecs > 0 {
		if err := m.setInt(ctx, "findtime", s.FindTimeSecs); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) getInt(ctx context.Context, param string) (int64, error) {
	v, err := m.client.Exec(ctx, "get", m.jail, param)
	if err != nil {
		return 0, err
	}
	n, ok := AsInt(v)
	if !ok {
		return 0, fmt.Errorf("f2b: get %s %s: non-numeric reply %q", m.jail, param, Stringify(v))
	}
	return n, nil
}

func (m *Manager) setInt(ctx context.Context, param string, val int64) error {
	v, err := m.client.Exec(ctx, "set", m.jail, param, strconv.FormatInt(val, 10))
	if err != nil {
		return fmt.Errorf("f2b: set %s %s=%d: %w", m.jail, param, val, err)
	}
	// The server echoes the effective value; verify it stuck.
	if n, ok := AsInt(v); ok && n != val {
		return fmt.Errorf("f2b: set %s %s=%d: server reports %d", m.jail, param, val, n)
	}
	return nil
}

// BanIP bans ip in the managed jail. Banning an already-banned IP is not an
// error.
func (m *Manager) BanIP(ctx context.Context, ip string) error {
	_, err := m.client.Exec(ctx, "set", m.jail, "banip", ip)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "already banned") {
		return nil
	}
	return err
}

// UnbanIP removes ip from the managed jail. Unbanning an IP that is not
// banned is not an error (keeps DB → firewall reconciliation idempotent).
func (m *Manager) UnbanIP(ctx context.Context, ip string) error {
	_, err := m.client.Exec(ctx, "set", m.jail, "unbanip", ip)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "not banned") {
		return nil
	}
	return err
}

// Banned returns the jail's currently banned IPs, extracted from the nested
// "status <jail>" response — the one shape that is stable across fail2ban
// versions.
func (m *Manager) Banned(ctx context.Context) ([]string, error) {
	v, err := m.client.Exec(ctx, "status", m.jail)
	if err != nil {
		return nil, err
	}
	if s, ok := v.(string); ok {
		// CLI fallback: parse the human-readable "Banned IP list:" line.
		return parseBannedFromCLI(s), nil
	}
	ips := []string{}
	if lst := findStatusList(v, "Banned IP list"); lst != nil {
		for _, e := range lst {
			if ip, ok := e.(string); ok && ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// findStatusList walks fail2ban's nested [[key, value], …] status structure
// looking for a key whose value is a list.
func findStatusList(v any, key string) []any {
	lst, ok := v.([]any)
	if !ok {
		return nil
	}
	if len(lst) == 2 {
		if k, ok := lst[0].(string); ok && k == key {
			if val, ok := lst[1].([]any); ok {
				return val
			}
			return nil
		}
	}
	for _, e := range lst {
		if r := findStatusList(e, key); r != nil {
			return r
		}
	}
	return nil
}

func parseBannedFromCLI(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Banned IP list") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return []string{}
		}
		raw := strings.TrimSpace(parts[1])
		if raw == "" {
			return []string{}
		}
		return strings.Fields(raw)
	}
	return []string{}
}
