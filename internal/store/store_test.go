package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/unwinds/sshwatch/internal/parse"
	"github.com/unwinds/sshwatch/internal/store"
)

func newTestStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeEvent(ip, evType string, ts time.Time) *parse.Event {
	return &parse.Event{
		TS:        ts,
		IP:        ip,
		EventType: evType,
		Username:  "testuser",
		Source:    "sshd",
	}
}

func TestInsertAndListEvents(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC().Truncate(time.Second)
	events := []*parse.Event{
		makeEvent("10.0.0.1", "failed_password", now.Add(-3*time.Hour)),
		makeEvent("10.0.0.2", "invalid_user", now.Add(-2*time.Hour)),
		makeEvent("10.0.0.1", "accepted", now.Add(-1*time.Hour)),
	}
	for _, e := range events {
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	rows, total, err := s.ListEvents(ctx, store.EventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 {
		t.Errorf("total: got %d, want 3", total)
	}
	if len(rows) != 3 {
		t.Fatalf("rows len: got %d, want 3", len(rows))
	}
	// Results are ordered by ts DESC, so most recent first.
	if rows[0].IP != "10.0.0.1" || rows[0].EventType != "accepted" {
		t.Errorf("first row: got ip=%s type=%s", rows[0].IP, rows[0].EventType)
	}
}

func TestListEventsFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	_ = s.InsertEvent(ctx, makeEvent("1.1.1.1", "failed_password", now.Add(-2*time.Second)))
	_ = s.InsertEvent(ctx, makeEvent("2.2.2.2", "accepted", now.Add(-1*time.Second)))
	_ = s.InsertEvent(ctx, makeEvent("1.1.1.1", "failed_password", now))

	rows, total, err := s.ListEvents(ctx, store.EventQuery{IP: "1.1.1.1", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 {
		t.Errorf("total: got %d, want 2", total)
	}
	for _, r := range rows {
		if r.IP != "1.1.1.1" {
			t.Errorf("unexpected ip: %s", r.IP)
		}
	}

	rows, total, err = s.ListEvents(ctx, store.EventQuery{EventType: "accepted", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Errorf("accepted filter: got total=%d rows=%d", total, len(rows))
	}
	if rows[0].EventType != "accepted" {
		t.Errorf("event type: got %q", rows[0].EventType)
	}
}

func TestGetStats(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	events := []*parse.Event{
		makeEvent("1.1.1.1", "failed_password", now.Add(-1*time.Hour)),
		makeEvent("2.2.2.2", "failed_password", now.Add(-2*time.Hour)),
		makeEvent("1.1.1.1", "accepted", now.Add(-30*time.Minute)),
		makeEvent("3.3.3.3", "invalid_user", now.Add(-10*time.Minute)),
	}
	for _, e := range events {
		if err := s.InsertEvent(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	st, err := s.GetStats(ctx, "24h")
	if err != nil {
		t.Fatalf("get stats: %v", err)
	}
	if st.TotalAttempts != 4 {
		t.Errorf("TotalAttempts: got %d, want 4", st.TotalAttempts)
	}
	if st.UniqueIPs != 3 {
		t.Errorf("UniqueIPs: got %d, want 3", st.UniqueIPs)
	}
	if st.Accepted != 1 {
		t.Errorf("Accepted: got %d, want 1", st.Accepted)
	}
	if st.Failed != 3 {
		t.Errorf("Failed: got %d, want 3", st.Failed)
	}
}

func TestRetention(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	old := now.AddDate(0, 0, -100)
	recent := now.Add(-time.Hour)

	_ = s.InsertEvent(ctx, makeEvent("1.1.1.1", "failed_password", old))
	_ = s.InsertEvent(ctx, makeEvent("2.2.2.2", "failed_password", old))
	_ = s.InsertEvent(ctx, makeEvent("3.3.3.3", "failed_password", recent))

	deleted, err := s.DeleteOldEvents(ctx, 90)
	if err != nil {
		t.Fatalf("delete old: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted: got %d, want 2", deleted)
	}

	_, total, _ := s.ListEvents(ctx, store.EventQuery{Limit: 10})
	if total != 1 {
		t.Errorf("remaining: got %d, want 1", total)
	}
}

func TestBanTracking(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	banEv := &parse.Event{
		TS:        now,
		IP:        "5.5.5.5",
		EventType: "ban",
		Username:  "sshd",
		Source:    "fail2ban",
	}
	if err := s.InsertEvent(ctx, banEv); err != nil {
		t.Fatalf("insert ban: %v", err)
	}

	bans, err := s.ListBans(ctx, true)
	if err != nil {
		t.Fatalf("list bans: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != "5.5.5.5" {
		t.Errorf("bans: got %v", bans)
	}
	if !bans[0].Active {
		t.Error("ban should be active")
	}

	// Unban.
	unbanEv := &parse.Event{
		TS:        now.Add(time.Hour),
		IP:        "5.5.5.5",
		EventType: "unban",
		Source:    "fail2ban",
	}
	if err := s.InsertEvent(ctx, unbanEv); err != nil {
		t.Fatalf("insert unban: %v", err)
	}

	bans, _ = s.ListBans(ctx, true)
	if len(bans) != 0 {
		t.Errorf("expected no active bans, got %d", len(bans))
	}
}

func TestInsertEvent_Dedup(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC().Truncate(time.Second)
	ev := makeEvent("1.2.3.4", "failed_password", now)

	if err := s.InsertEvent(ctx, ev); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := s.InsertEvent(ctx, ev); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("second insert: want ErrDuplicate, got %v", err)
	}

	_, total, _ := s.ListEvents(ctx, store.EventQuery{IP: "1.2.3.4", Limit: 10})
	if total != 1 {
		t.Errorf("want 1 row after dedup, got %d", total)
	}
}

func TestBanIPAndUnbanIP(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.BanIP(ctx, "203.0.113.5", "nftables", "manual test"); err != nil {
		t.Fatalf("BanIP: %v", err)
	}

	bans, err := s.ListBans(ctx, true)
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 ban, got %d", len(bans))
	}
	if bans[0].IP != "203.0.113.5" {
		t.Errorf("IP: %q", bans[0].IP)
	}
	if !bans[0].Active {
		t.Error("want active=true")
	}
	if bans[0].Source != "nftables" {
		t.Errorf("Source: %q", bans[0].Source)
	}
	if bans[0].Reason != "manual test" {
		t.Errorf("Reason: %q", bans[0].Reason)
	}

	if err := s.UnbanIP(ctx, "203.0.113.5"); err != nil {
		t.Fatalf("UnbanIP: %v", err)
	}

	bans, _ = s.ListBans(ctx, true)
	if len(bans) != 0 {
		t.Errorf("want 0 active bans after unban, got %d", len(bans))
	}
	all, _ := s.ListBans(ctx, false)
	if len(all) != 1 || all[0].Active {
		t.Errorf("want 1 inactive ban in history, got %v", all)
	}
}
