package notify

import (
	"context"
	"testing"
	"time"

	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/store"
)

// --- mock Notifier ---

type mockNotifier struct {
	msgs []Message
}

func (m *mockNotifier) Send(_ context.Context, msg Message) error {
	m.msgs = append(m.msgs, msg)
	return nil
}
func (m *mockNotifier) Name() string { return "mock" }

// --- stub Store (only CountIPEvents is exercised) ---

type stubStore struct {
	countResult int64
}

func (s *stubStore) CountIPEvents(_ context.Context, _ string, _ time.Time) (int64, error) {
	return s.countResult, nil
}
func (s *stubStore) InsertEvent(context.Context, *parse.Event) error                     { return nil }
func (s *stubStore) ListEvents(context.Context, store.EventQuery) ([]store.EventRow, int64, error) {
	return nil, 0, nil
}
func (s *stubStore) GetStats(context.Context, string) (*store.Stats, error)       { return nil, nil }
func (s *stubStore) ListBans(context.Context, bool) ([]store.BanRow, error)       { return nil, nil }
func (s *stubStore) GetMapPoints(context.Context, string) ([]store.MapPoint, error) { return nil, nil }
func (s *stubStore) DeleteOldEvents(context.Context, int) (int64, error)          { return 0, nil }
func (s *stubStore) BanIP(context.Context, string, string, string) error                    { return nil }
func (s *stubStore) UnbanIP(context.Context, string) error                                  { return nil }
func (s *stubStore) GetSetting(context.Context, string) (string, bool, error)               { return "", false, nil }
func (s *stubStore) SetSetting(context.Context, string, string) error                       { return nil }
func (s *stubStore) GetAllSettings(context.Context) (map[string]string, error)              { return nil, nil }
func (s *stubStore) Close() error                                                            { return nil }

// --- helpers ---

func makeDispatcher(t *testing.T, ruleStrs []string, n Notifier, st store.Store) (*Dispatcher, *mockNotifier) {
	t.Helper()
	mn, ok := n.(*mockNotifier)
	if !ok {
		mn = &mockNotifier{}
		n = mn
	}
	rules, err := parseRules(ruleStrs)
	if err != nil {
		t.Fatalf("parseRules: %v", err)
	}
	d := &Dispatcher{notifiers: []Notifier{n}, rules: rules, st: st}
	return d, mn
}

func event(typ, ip, country string) *parse.Event {
	return &parse.Event{
		TS:        time.Now().UTC(),
		IP:        ip,
		EventType: typ,
		Username:  "testuser",
		Geo:       parse.GeoInfo{Country: country},
	}
}

// --- tests ---

func TestParseRules_unknown(t *testing.T) {
	_, err := parseRules([]string{"unknown_rule"})
	if err == nil {
		t.Fatal("expected error for unknown rule")
	}
}

func TestParseRules_threshold_bad(t *testing.T) {
	cases := []string{
		"threshold:",
		"threshold:abc/1h",
		"threshold:100",
		"threshold:100/notaduration",
		"threshold:0/1h",
	}
	for _, s := range cases {
		if _, err := parseRules([]string{s}); err == nil {
			t.Errorf("parseRules(%q): expected error, got nil", s)
		}
	}
}

func TestParseRules_threshold_ok(t *testing.T) {
	rules, err := parseRules([]string{"threshold:100/1h"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	r := rules[0].(*thresholdRule)
	if r.n != 100 || r.window != time.Hour {
		t.Errorf("got n=%d window=%s", r.n, r.window)
	}
}

func TestAcceptedLoginRule_fires(t *testing.T) {
	d, mn := makeDispatcher(t, []string{"accepted_login"}, &mockNotifier{}, nil)
	ctx := context.Background()

	d.dispatch(ctx, event("accepted", "1.2.3.4", "DE"))
	if len(mn.msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(mn.msgs))
	}
	if mn.msgs[0].EventType != "accepted" {
		t.Errorf("want event_type accepted, got %s", mn.msgs[0].EventType)
	}
}

func TestAcceptedLoginRule_nofire_on_failed(t *testing.T) {
	d, mn := makeDispatcher(t, []string{"accepted_login"}, &mockNotifier{}, nil)
	d.dispatch(context.Background(), event("failed_password", "1.2.3.4", "CN"))
	if len(mn.msgs) != 0 {
		t.Errorf("want 0 messages, got %d", len(mn.msgs))
	}
}

func TestBanRule_fires(t *testing.T) {
	d, mn := makeDispatcher(t, []string{"ban"}, &mockNotifier{}, nil)
	d.dispatch(context.Background(), event("ban", "5.6.7.8", "RU"))
	if len(mn.msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(mn.msgs))
	}
	if mn.msgs[0].Title != "SSH: IP Banned" {
		t.Errorf("unexpected title: %s", mn.msgs[0].Title)
	}
}

func TestBanRule_nofire_on_unban(t *testing.T) {
	d, mn := makeDispatcher(t, []string{"ban"}, &mockNotifier{}, nil)
	d.dispatch(context.Background(), event("unban", "5.6.7.8", "RU"))
	if len(mn.msgs) != 0 {
		t.Errorf("want 0 messages, got %d", len(mn.msgs))
	}
}

func TestNewCountryRule_first_fires_second_does_not(t *testing.T) {
	d, mn := makeDispatcher(t, []string{"new_country"}, &mockNotifier{}, nil)
	ctx := context.Background()

	d.dispatch(ctx, event("failed_password", "1.1.1.1", "JP"))
	d.dispatch(ctx, event("failed_password", "2.2.2.2", "JP")) // same country
	d.dispatch(ctx, event("failed_password", "3.3.3.3", "BR")) // new country

	if len(mn.msgs) != 2 {
		t.Fatalf("want 2 messages (JP + BR), got %d", len(mn.msgs))
	}
	if mn.msgs[0].Country != "JP" || mn.msgs[1].Country != "BR" {
		t.Errorf("unexpected countries: %v %v", mn.msgs[0].Country, mn.msgs[1].Country)
	}
}

func TestNewCountryRule_no_country_skipped(t *testing.T) {
	d, mn := makeDispatcher(t, []string{"new_country"}, &mockNotifier{}, nil)
	d.dispatch(context.Background(), event("failed_password", "1.2.3.4", ""))
	if len(mn.msgs) != 0 {
		t.Errorf("want 0 messages for empty country, got %d", len(mn.msgs))
	}
}

func TestThresholdRule_fires_when_exceeded(t *testing.T) {
	st := &stubStore{countResult: 150}
	d, mn := makeDispatcher(t, []string{"threshold:100/1h"}, &mockNotifier{}, st)
	d.dispatch(context.Background(), event("failed_password", "9.9.9.9", "US"))
	if len(mn.msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(mn.msgs))
	}
}

func TestThresholdRule_no_fire_below_threshold(t *testing.T) {
	st := &stubStore{countResult: 50}
	d, mn := makeDispatcher(t, []string{"threshold:100/1h"}, &mockNotifier{}, st)
	d.dispatch(context.Background(), event("failed_password", "9.9.9.9", "US"))
	if len(mn.msgs) != 0 {
		t.Errorf("want 0 messages, got %d", len(mn.msgs))
	}
}

func TestThresholdRule_cooldown(t *testing.T) {
	st := &stubStore{countResult: 200}
	d, mn := makeDispatcher(t, []string{"threshold:100/1h"}, &mockNotifier{}, st)
	ctx := context.Background()

	d.dispatch(ctx, event("failed_password", "9.9.9.9", "US"))
	d.dispatch(ctx, event("failed_password", "9.9.9.9", "US")) // same IP, within cooldown
	if len(mn.msgs) != 1 {
		t.Errorf("want 1 message (cooldown), got %d", len(mn.msgs))
	}
}

func TestNilDispatcher_safe(t *testing.T) {
	var d *Dispatcher
	d.Notify(event("accepted", "1.2.3.4", "DE")) // must not panic
}

func TestEscapeHTML(t *testing.T) {
	cases := []struct{ in, want string }{
		{"<b>test</b>", "&lt;b&gt;test&lt;/b&gt;"},
		{"a & b", "a &amp; b"},
		{"normal", "normal"},
	}
	for _, tc := range cases {
		got := escapeHTML(tc.in)
		if got != tc.want {
			t.Errorf("escapeHTML(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
