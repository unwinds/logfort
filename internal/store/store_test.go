package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/store"
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

func TestListEventsUsernameFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	e1 := makeEvent("1.1.1.1", "failed_password", now.Add(-2*time.Second))
	e1.Username = "root"
	e2 := makeEvent("2.2.2.2", "failed_password", now.Add(-1*time.Second))
	e2.Username = "admin"
	_ = s.InsertEvent(ctx, e1)
	_ = s.InsertEvent(ctx, e2)

	rows, total, err := s.ListEvents(ctx, store.EventQuery{Username: "root", Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Username != "root" {
		t.Errorf("username filter: total=%d rows=%d", total, len(rows))
	}
}

func TestPing(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestBackup(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	_ = s.InsertEvent(ctx, makeEvent("1.1.1.1", "failed_password", now))
	_ = s.InsertEvent(ctx, makeEvent("2.2.2.2", "accepted", now.Add(-time.Second)))

	dst := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(ctx, dst); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// The snapshot must be a valid database containing the same events.
	restored, err := store.New(dst)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer restored.Close()
	_, total, err := restored.ListEvents(ctx, store.EventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list from backup: %v", err)
	}
	if total != 2 {
		t.Errorf("backup total events: got %d, want 2", total)
	}

	// A second backup to the same (now existing) path must fail loudly, not
	// silently truncate.
	if err := s.Backup(ctx, dst); err == nil {
		t.Error("want error when destination already exists")
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
	if st.BucketSecs != 3600 {
		t.Errorf("BucketSecs for 24h: got %d, want 3600", st.BucketSecs)
	}
}

func TestGetStats_BucketSecsPerWindow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	want := map[string]int64{"1h": 300, "6h": 1800, "24h": 3600, "7d": 86400, "30d": 86400, "all": 86400}
	for window, secs := range want {
		st, err := s.GetStats(ctx, window)
		if err != nil {
			t.Fatalf("GetStats(%s): %v", window, err)
		}
		if st.BucketSecs != secs {
			t.Errorf("BucketSecs(%s): got %d, want %d", window, st.BucketSecs, secs)
		}
	}
}

func TestListEvents_EmptyIsNonNil(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	rows, total, err := s.ListEvents(ctx, store.EventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 0 {
		t.Errorf("total: %d", total)
	}
	if rows == nil {
		t.Error("empty result must be a non-nil slice (JSON [] not null)")
	}

	points, err := s.GetMapPoints(ctx, "24h")
	if err != nil {
		t.Fatalf("map points: %v", err)
	}
	if points == nil {
		t.Error("empty map points must be a non-nil slice")
	}
}

func TestCountIPEvents_CountsOnlyPrimaryAttempts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	// 3 accepted logins (legit automation) — never counted.
	for i := 0; i < 3; i++ {
		_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "accepted", now.Add(-time.Duration(i+1)*time.Minute)))
	}
	// One real wrong-password attempt against an unknown user produces all
	// four of these lines; only failed_password may count, otherwise a single
	// attempt is counted 3-4 times and thresholds fire way too early.
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "failed_password", now.Add(-10*time.Minute)))
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "invalid_user", now.Add(-10*time.Minute)))
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "pam_failure", now.Add(-10*time.Minute)))
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "disconnect_preauth", now.Add(-9*time.Minute)))
	// A second attempt plus an nginx auth failure and a max_auth line.
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "failed_password", now.Add(-8*time.Minute)))
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "http_auth_fail", now.Add(-7*time.Minute)))
	_ = s.InsertEvent(ctx, makeEvent("7.7.7.7", "max_auth", now.Add(-6*time.Minute)))

	count, err := s.CountIPEvents(ctx, "7.7.7.7", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 4 {
		t.Errorf("count: got %d, want 4 (2 failed_password + http_auth_fail + max_auth)", count)
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

func TestRetention_PrunesInactiveBans(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Old active ban, old inactive ban, recent inactive ban.
	if err := s.BanIP(ctx, "1.1.1.1", "nftables", "keep: active", 0); err != nil {
		t.Fatal(err)
	}
	oldTS := time.Now().AddDate(0, 0, -100)
	_ = s.InsertEvent(ctx, &parse.Event{TS: oldTS, IP: "2.2.2.2", EventType: "ban", Source: "fail2ban"})
	_ = s.InsertEvent(ctx, &parse.Event{TS: oldTS.Add(time.Hour), IP: "2.2.2.2", EventType: "unban", Source: "fail2ban"})

	if _, err := s.DeleteOldEvents(ctx, 90); err != nil {
		t.Fatalf("retention: %v", err)
	}

	all, err := s.ListBans(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].IP != "1.1.1.1" || !all[0].Active {
		t.Errorf("want only the active ban to survive, got %+v", all)
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

func TestListExpiredBans(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now()
	// Permanent ban, expired ban, not-yet-expired ban.
	if err := s.BanIP(ctx, "1.1.1.1", "nftables", "permanent", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.BanIP(ctx, "2.2.2.2", "nftables", "expired", now.Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := s.BanIP(ctx, "3.3.3.3", "nftables", "future", now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	expired, err := s.ListExpiredBans(ctx, now)
	if err != nil {
		t.Fatalf("ListExpiredBans: %v", err)
	}
	if len(expired) != 1 || expired[0].IP != "2.2.2.2" {
		t.Fatalf("want only 2.2.2.2 expired, got %+v", expired)
	}
	if expired[0].ExpiresAt == nil {
		t.Fatal("expired ban must carry expires_at")
	}

	// After the sweeper unbans it, it must not come back.
	if err := s.UnbanIP(ctx, "2.2.2.2"); err != nil {
		t.Fatalf("UnbanIP: %v", err)
	}
	expired, err = s.ListExpiredBans(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 0 {
		t.Fatalf("want no expired bans after unban, got %+v", expired)
	}

	// The permanent ban keeps a nil expires_at through ListBans.
	active, err := s.ListBans(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range active {
		if b.IP == "1.1.1.1" && b.ExpiresAt != nil {
			t.Errorf("permanent ban must have nil expires_at, got %d", *b.ExpiresAt)
		}
		if b.IP == "3.3.3.3" && b.ExpiresAt == nil {
			t.Error("TTL ban must have non-nil expires_at")
		}
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

	if err := s.BanIP(ctx, "203.0.113.5", "nftables", "manual test", 0); err != nil {
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
