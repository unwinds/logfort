package notify

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/unwinds/sshwatch/internal/config"
	"github.com/unwinds/sshwatch/internal/parse"
	"github.com/unwinds/sshwatch/internal/store"
)

// Dispatcher evaluates notification rules and delivers matching alerts.
type Dispatcher struct {
	notifiers []Notifier
	rules     []rule
	st        store.Store
}

// New builds a Dispatcher from config. Returns nil if no notifiers or no rules
// are configured — callers must nil-check before use.
func New(cfg *config.Config, st store.Store) (*Dispatcher, error) {
	var notifiers []Notifier
	if cfg.NotifyWebhookURL != "" {
		notifiers = append(notifiers, NewWebhook(cfg.NotifyWebhookURL))
	}
	if cfg.NotifyTelegramToken != "" && cfg.NotifyTelegramChat != "" {
		notifiers = append(notifiers, NewTelegram(cfg.NotifyTelegramToken, cfg.NotifyTelegramChat))
	}
	if cfg.NotifyDiscordURL != "" {
		notifiers = append(notifiers, NewDiscord(cfg.NotifyDiscordURL))
	}
	if len(notifiers) == 0 {
		return nil, nil
	}
	if len(cfg.NotifyRules) == 0 {
		slog.Warn("notify: notifiers configured but SSHWATCH_NOTIFY_RULES is empty — no alerts will fire")
		return nil, nil
	}
	rules, err := parseRules(cfg.NotifyRules)
	if err != nil {
		return nil, fmt.Errorf("notify rules: %w", err)
	}
	return &Dispatcher{notifiers: notifiers, rules: rules, st: st}, nil
}

// Notify evaluates rules against ev and dispatches matching notifications in a
// background goroutine so the caller is never blocked on network I/O.
// Safe to call on a nil Dispatcher.
func (d *Dispatcher) Notify(ev *parse.Event) {
	if d == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		d.dispatch(ctx, ev)
	}()
}

// dispatch is the synchronous core used by Notify and by tests.
func (d *Dispatcher) dispatch(ctx context.Context, ev *parse.Event) {
	for _, r := range d.rules {
		msg := r.match(ctx, ev, d.st)
		if msg == nil {
			continue
		}
		for _, n := range d.notifiers {
			if err := n.Send(ctx, *msg); err != nil {
				slog.Warn("notify send failed", "notifier", n.Name(), "rule", msg.EventType, "ip", ev.IP, "err", err)
			}
		}
	}
}
