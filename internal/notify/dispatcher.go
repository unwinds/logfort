package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/store"
)

// Dispatcher evaluates notification rules and delivers matching alerts.
type Dispatcher struct {
	notifiers []Notifier
	rules     []rule
	st        store.Store
	ctx       context.Context
	cancel    context.CancelFunc
	startedAt time.Time
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
		slog.Warn("notify: notifiers configured but LOGFORT_NOTIFY_RULES is empty — no alerts will fire")
		return nil, nil
	}
	rules, err := parseRules(cfg.NotifyRules)
	if err != nil {
		return nil, fmt.Errorf("notify rules: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Dispatcher{notifiers: notifiers, rules: rules, st: st, ctx: ctx, cancel: cancel, startedAt: time.Now()}, nil
}

// Stop cancels all in-flight Notify goroutines. Safe to call on a nil Dispatcher.
func (d *Dispatcher) Stop() {
	if d != nil {
		d.cancel()
	}
}

// Notify evaluates rules against ev and dispatches matching notifications in a
// background goroutine so the caller is never blocked on network I/O.
// Safe to call on a nil Dispatcher.
func (d *Dispatcher) Notify(ev *parse.Event) {
	if d == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(d.ctx, 15*time.Second)
		defer cancel()
		d.dispatch(ctx, ev)
	}()
}

// SendTest delivers a fixed test message directly to every configured
// notifier, bypassing rule evaluation, and returns the first delivery error.
// Rules are intentionally skipped: the point of a test is to verify the
// channel works even when no rule would match a synthetic event.
func (d *Dispatcher) SendTest(ctx context.Context) error {
	if d == nil {
		return errors.New("no notifiers configured")
	}
	msg := Message{
		Title:     "LogFort: Test Notification",
		Body:      "If you can read this, the notification channel works.",
		EventType: "test",
		TS:        time.Now().Unix(),
	}
	var firstErr error
	for _, n := range d.notifiers {
		if err := n.Send(ctx, msg); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", n.Name(), err)
		}
	}
	return firstErr
}

// dispatch is the synchronous core used by Notify and by tests.
func (d *Dispatcher) dispatch(ctx context.Context, ev *parse.Event) {
	// Suppress notifications for events that pre-date startup — prevents flooding
	// when fail2ban.log is replayed from the beginning to reconstruct ban state.
	if ev.TS.Before(d.startedAt.Add(-time.Minute)) {
		return
	}
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
