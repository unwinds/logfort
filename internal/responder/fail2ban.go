package responder

import (
	"context"

	"github.com/unwinds/logfort/internal/f2b"
)

// Fail2BanResponder delegates bans to the fail2ban server. It talks to the
// fail2ban command socket directly (works inside a container with
// /var/run/fail2ban mounted — no fail2ban-client binary required) and falls
// back to the fail2ban-client CLI when the socket is absent.
type Fail2BanResponder struct {
	mgr *f2b.Manager
}

func newFail2BanResponder(socketPath, jail string) *Fail2BanResponder {
	return &Fail2BanResponder{mgr: f2b.NewManager(socketPath, jail)}
}

// NewFail2BanFromManager wires an existing manager (shared with the settings
// API) into a responder.
func NewFail2BanFromManager(mgr *f2b.Manager) *Fail2BanResponder {
	return &Fail2BanResponder{mgr: mgr}
}

func (r *Fail2BanResponder) Name() string { return "fail2ban" }

func (r *Fail2BanResponder) Ban(ctx context.Context, ip string) error {
	return r.mgr.BanIP(ctx, ip)
}

func (r *Fail2BanResponder) Unban(ctx context.Context, ip string) error {
	return r.mgr.UnbanIP(ctx, ip)
}

func (r *Fail2BanResponder) List(ctx context.Context) ([]string, error) {
	return r.mgr.Banned(ctx)
}
