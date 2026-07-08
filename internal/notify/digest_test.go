package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/store"
)

// digestStore returns canned stats for digest tests.
type digestStore struct {
	stubStore
	stats store.Stats
}

func (s *digestStore) GetStats(context.Context, string) (*store.Stats, error) {
	st := s.stats
	return &st, nil
}

func TestParseRules_Digest(t *testing.T) {
	rules, digests, err := parseRules([]string{"ban", "digest:daily", "digest:weekly"})
	if err != nil {
		t.Fatalf("parseRules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("want 1 event rule, got %d", len(rules))
	}
	if len(digests) != 2 || digests[0].label != "daily" || digests[1].label != "weekly" {
		t.Errorf("digests: %+v", digests)
	}
	if digests[0].window != "24h" || digests[1].window != "7d" {
		t.Errorf("digest windows: %+v", digests)
	}

	if _, _, err := parseRules([]string{"digest:hourly"}); err == nil {
		t.Error("digest:hourly must be rejected")
	}
}

func TestNew_ValidatesRulesWithoutNotifiers(t *testing.T) {
	// Bad rule syntax must be rejected even when no notifier is configured:
	// the settings API validates with notify.New, and a silently-persisted
	// broken rule string becomes a startup failure once a notifier is added.
	cfg := &config.Config{NotifyRules: []string{"digest:hourly"}}
	if _, err := New(cfg, nil); err == nil {
		t.Fatal("want error for bad rule with no notifiers, got nil")
	}
}

func TestDigestSchedule_Next(t *testing.T) {
	daily := digestSchedule{label: "daily", window: "24h"}
	weekly := digestSchedule{label: "weekly", window: "7d"}

	// Wednesday 2026-07-08 10:00 local → daily fires Thursday 09:00.
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.Local)
	next := daily.next(now)
	if next.Day() != 9 || next.Hour() != digestHour {
		t.Errorf("daily next: %v", next)
	}

	// Before 09:00 the same day still counts.
	now = time.Date(2026, 7, 8, 8, 0, 0, 0, time.Local)
	next = daily.next(now)
	if next.Day() != 8 || next.Hour() != digestHour {
		t.Errorf("daily next same-day: %v", next)
	}

	// Weekly always lands on a Monday strictly after now.
	next = weekly.next(now)
	if next.Weekday() != time.Monday || !next.After(now) || next.Hour() != digestHour {
		t.Errorf("weekly next: %v", next)
	}
	// From a Monday after digest hour, next fire is the following Monday.
	monday := time.Date(2026, 7, 6, 12, 0, 0, 0, time.Local)
	next = weekly.next(monday)
	if next.Weekday() != time.Monday || next.Day() != 13 {
		t.Errorf("weekly from monday: %v", next)
	}
}

func TestSendDigest(t *testing.T) {
	st := &digestStore{stats: store.Stats{
		TotalAttempts:   150,
		UniqueIPs:       12,
		Failed:          140,
		Accepted:        10,
		CurrentlyBanned: 3,
		TopIPs:          []store.TopIP{{IP: "203.0.113.5", Count: 90, Country: "CN"}},
		TopUsernames:    []store.TopUsername{{Username: "root", Count: 80}},
		TopCountries:    []store.TopCountry{{Country: "CN", Count: 100}},
	}}
	mn := &mockNotifier{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Dispatcher{notifiers: []Notifier{mn}, st: st, ctx: ctx, cancel: cancel}

	d.sendDigest(digestSchedule{label: "daily", window: "24h"})

	msgs := mn.msgs
	if len(msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(msgs))
	}
	m := msgs[0]
	if m.Title != "LogFort: Daily Digest" || m.EventType != "digest" {
		t.Errorf("title/type: %q %q", m.Title, m.EventType)
	}
	for _, want := range []string{"140 failed attempts", "12 IPs", "10 accepted", "Currently banned: 3", "203.0.113.5", "root", "CN"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("body missing %q:\n%s", want, m.Body)
		}
	}
}

func TestSendDigest_Quiet(t *testing.T) {
	st := &digestStore{stats: store.Stats{}}
	mn := &mockNotifier{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Dispatcher{notifiers: []Notifier{mn}, st: st, ctx: ctx, cancel: cancel}

	d.sendDigest(digestSchedule{label: "weekly", window: "7d"})

	msgs := mn.msgs
	if len(msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Body, "All quiet") {
		t.Errorf("quiet digest body: %s", msgs[0].Body)
	}
	if msgs[0].Title != "LogFort: Weekly Digest" {
		t.Errorf("title: %q", msgs[0].Title)
	}
}
