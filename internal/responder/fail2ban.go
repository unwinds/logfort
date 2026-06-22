package responder

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Fail2BanResponder delegates bans to the fail2ban-client binary.
type Fail2BanResponder struct {
	jail string
}

func newFail2BanResponder(jail string) *Fail2BanResponder {
	return &Fail2BanResponder{jail: jail}
}

func (r *Fail2BanResponder) Name() string { return "fail2ban" }

func (r *Fail2BanResponder) Ban(ctx context.Context, ip string) error {
	return r.run(ctx, "set", r.jail, "banip", ip)
}

func (r *Fail2BanResponder) Unban(ctx context.Context, ip string) error {
	return r.run(ctx, "set", r.jail, "unbanip", ip)
}

func (r *Fail2BanResponder) List(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "fail2ban-client", "status", r.jail).Output()
	if err != nil {
		return nil, fmt.Errorf("fail2ban-client status %s: %w", r.jail, err)
	}
	// Parse "Banned IP list: 1.2.3.4 5.6.7.8" from the status output
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Banned IP list") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				raw := strings.TrimSpace(parts[1])
				if raw == "" {
					return []string{}, nil
				}
				return strings.Fields(raw), nil
			}
		}
	}
	return []string{}, nil
}

func (r *Fail2BanResponder) run(ctx context.Context, args ...string) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "fail2ban-client", args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("fail2ban-client %s: %s", strings.Join(args, " "), msg)
		}
		return fmt.Errorf("fail2ban-client %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
