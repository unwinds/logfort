package notify

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unwinds/sshwatch/internal/parse"
	"github.com/unwinds/sshwatch/internal/store"
)

// rule evaluates an event and returns a Message to send, or nil to skip.
type rule interface {
	match(ctx context.Context, ev *parse.Event, st store.Store) *Message
}

// --- accepted_login ---

type acceptedLoginRule struct{}

func (acceptedLoginRule) match(_ context.Context, ev *parse.Event, _ store.Store) *Message {
	if ev.EventType != "accepted" {
		return nil
	}
	body := fmt.Sprintf("User %q logged in from %s", ev.Username, ev.IP)
	if ev.Geo.Country != "" {
		body += " (" + ev.Geo.Country
		if ev.Geo.City != "" {
			body += ", " + ev.Geo.City
		}
		body += ")"
	}
	if ev.AuthMethod != "" {
		body += "\nMethod: " + ev.AuthMethod
	}
	return &Message{
		Title:     "SSH: Accepted Login",
		Body:      body,
		IP:        ev.IP,
		EventType: ev.EventType,
		Country:   ev.Geo.Country,
		TS:        ev.TS.Unix(),
	}
}

// --- ban ---

type banRule struct{}

func (banRule) match(_ context.Context, ev *parse.Event, _ store.Store) *Message {
	if ev.EventType != "ban" {
		return nil
	}
	body := ev.IP + " was banned"
	if ev.Geo.Country != "" {
		body += " (" + ev.Geo.Country + ")"
	}
	if ev.Source != "" && ev.Source != "fail2ban" {
		body += " [" + ev.Source + "]"
	}
	return &Message{
		Title:     "SSH: IP Banned",
		Body:      body,
		IP:        ev.IP,
		EventType: ev.EventType,
		Country:   ev.Geo.Country,
		TS:        ev.TS.Unix(),
	}
}

// --- new_country ---

type newCountryRule struct {
	seen sync.Map
}

func (r *newCountryRule) match(_ context.Context, ev *parse.Event, _ store.Store) *Message {
	if ev.Geo.Country == "" {
		return nil
	}
	if _, loaded := r.seen.LoadOrStore(ev.Geo.Country, struct{}{}); loaded {
		return nil
	}
	body := fmt.Sprintf("First attack from %s", ev.Geo.Country)
	if ev.Geo.City != "" {
		body += " (" + ev.Geo.City + ")"
	}
	body += "\nIP: " + ev.IP
	return &Message{
		Title:     "SSH: New Country",
		Body:      body,
		IP:        ev.IP,
		EventType: ev.EventType,
		Country:   ev.Geo.Country,
		TS:        ev.TS.Unix(),
	}
}

// --- threshold:N/Xh ---

type thresholdRule struct {
	n      int64
	window time.Duration
	// fired tracks the last notification time per IP to avoid repeated alerts
	// within the same window.
	fired sync.Map
}

func (r *thresholdRule) match(ctx context.Context, ev *parse.Event, st store.Store) *Message {
	if ev.IP == "" || st == nil {
		return nil
	}
	now := time.Now()
	if last, ok := r.fired.Load(ev.IP); ok {
		if now.Sub(last.(time.Time)) < r.window {
			return nil
		}
	}
	count, err := st.CountIPEvents(ctx, ev.IP, now.Add(-r.window))
	if err != nil || count < r.n {
		return nil
	}
	r.fired.Store(ev.IP, now)
	body := fmt.Sprintf("%s made %d attempts in the last %s", ev.IP, count, r.window)
	if ev.Geo.Country != "" {
		body += " (" + ev.Geo.Country + ")"
	}
	return &Message{
		Title:     "SSH: Threshold Exceeded",
		Body:      body,
		IP:        ev.IP,
		EventType: ev.EventType,
		Country:   ev.Geo.Country,
		TS:        ev.TS.Unix(),
	}
}

// parseRules converts config rule strings into rule instances.
func parseRules(strs []string) ([]rule, error) {
	var rules []rule
	for _, s := range strs {
		s = strings.TrimSpace(s)
		switch {
		case s == "accepted_login":
			rules = append(rules, acceptedLoginRule{})
		case s == "ban":
			rules = append(rules, banRule{})
		case s == "new_country":
			rules = append(rules, &newCountryRule{})
		case strings.HasPrefix(s, "threshold:"):
			r, err := parseThresholdRule(s)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r)
		default:
			return nil, fmt.Errorf("unknown notify rule %q; valid: accepted_login, ban, new_country, threshold:N/Xd", s)
		}
	}
	return rules, nil
}

// parseThresholdRule parses "threshold:N/Xh" into a thresholdRule.
// The window must be a valid Go duration (e.g. 1h, 30m, 24h).
func parseThresholdRule(s string) (*thresholdRule, error) {
	rest := strings.TrimPrefix(s, "threshold:")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("threshold rule format is threshold:N/dur (e.g. threshold:100/1h), got %q", s)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("threshold count must be a positive integer in %q", s)
	}
	d, err := time.ParseDuration(strings.TrimSpace(parts[1]))
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("threshold window must be a valid Go duration (e.g. 1h, 30m) in %q", s)
	}
	return &thresholdRule{n: n, window: d}, nil
}
