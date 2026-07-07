package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/unwinds/logfort/internal/api"
	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/responder"
	"github.com/unwinds/logfort/internal/store"
)

// mockStore is a minimal in-memory store for API tests.
type mockStore struct {
	bannedIPs   []string
	unbannedIPs []string
	saved       map[string]string // records SetSettings writes
	pingErr     error             // returned by Ping (health db probe)
}

func (m *mockStore) InsertEvent(_ context.Context, _ *parse.Event) error { return nil }
func (m *mockStore) ListEvents(_ context.Context, _ store.EventQuery) ([]store.EventRow, int64, error) {
	return []store.EventRow{}, 0, nil
}
func (m *mockStore) GetStats(_ context.Context, _ string) (*store.Stats, error) {
	return &store.Stats{
		TopIPs: []store.TopIP{}, TopCountries: []store.TopCountry{},
		TopUsernames: []store.TopUsername{}, Timeline: []store.TimeBucket{},
	}, nil
}
func (m *mockStore) ListBans(_ context.Context, _ bool) ([]store.BanRow, error) {
	return []store.BanRow{}, nil
}
func (m *mockStore) GetMapPoints(_ context.Context, _ string) ([]store.MapPoint, error) {
	return []store.MapPoint{}, nil
}
func (m *mockStore) DeleteOldEvents(_ context.Context, _ int) (int64, error) { return 0, nil }
func (m *mockStore) BanIP(_ context.Context, ip, _, _ string) error {
	m.bannedIPs = append(m.bannedIPs, ip)
	return nil
}
func (m *mockStore) UnbanIP(_ context.Context, ip string) error {
	m.unbannedIPs = append(m.unbannedIPs, ip)
	return nil
}
func (m *mockStore) CountIPEvents(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *mockStore) GetSetting(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}
func (m *mockStore) SetSetting(_ context.Context, _, _ string) error { return nil }
func (m *mockStore) SetSettings(_ context.Context, pairs map[string]string) error {
	if m.saved == nil {
		m.saved = map[string]string{}
	}
	for k, v := range pairs {
		m.saved[k] = v
	}
	return nil
}
func (m *mockStore) GetAllSettings(_ context.Context) (map[string]string, error) { return nil, nil }
func (m *mockStore) Ping(_ context.Context) error                                { return m.pingErr }
func (m *mockStore) Backup(_ context.Context, dstPath string) error {
	// Simulate VACUUM INTO: write a small fake snapshot to dstPath.
	return os.WriteFile(dstPath, []byte("SQLite format 3\x00fake-backup"), 0o600)
}
func (m *mockStore) Close() error { return nil }

// mockResponder tracks ban/unban calls.
type mockResponder struct {
	banned   []string
	unbanned []string
}

func (mr *mockResponder) Ban(_ context.Context, ip string) error {
	mr.banned = append(mr.banned, ip)
	return nil
}
func (mr *mockResponder) Unban(_ context.Context, ip string) error {
	mr.unbanned = append(mr.unbanned, ip)
	return nil
}
func (mr *mockResponder) List(_ context.Context) ([]string, error) { return mr.banned, nil }
func (mr *mockResponder) Name() string                             { return "mock" }

func newTestServer(t *testing.T, responderEnabled bool) (*api.Server, *mockStore, *mockResponder) {
	t.Helper()
	cfg := &config.Config{
		Listen:           "127.0.0.1:0",
		ResponderEnabled: responderEnabled,
		ResponderBackend: "mock",
		IgnoreIPs:        []string{"127.0.0.0/8", "10.0.0.0/8"},
		RetentionDays:    90,
		AuthEnabled:      false,
	}
	ms := &mockStore{}
	srv := api.New(cfg, ms, "test")

	mr := &mockResponder{}
	al, err := responder.ParseAllowlist(cfg.IgnoreIPs)
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	srv.SetResponder(mr, al)
	return srv, ms, mr
}

func postJSON(t *testing.T, srv http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.99:12345" // external IP as requester
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestBanPost_ResponderDisabled(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := postJSON(t, srv, "/api/ban", map[string]string{"ip": "203.0.113.5"})
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnbanPost_ResponderDisabled(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := postJSON(t, srv, "/api/unban", map[string]string{"ip": "203.0.113.5"})
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBanPost_InvalidIP(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	w := postJSON(t, srv, "/api/ban", map[string]string{"ip": "not-an-ip"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestBanPost_AllowlistedIP(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	w := postJSON(t, srv, "/api/ban", map[string]string{"ip": "10.0.0.1"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for allowlisted IP, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBanPost_PrivateIP(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	w := postJSON(t, srv, "/api/ban", map[string]string{"ip": "192.168.1.1"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for private IP, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBanPost_SelfLockout(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	// The requester IP is 203.0.113.99 (set in postJSON).
	w := postJSON(t, srv, "/api/ban", map[string]string{"ip": "203.0.113.99"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for self-lockout, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBanPost_Success(t *testing.T) {
	srv, ms, mr := newTestServer(t, true)
	w := postJSON(t, srv, "/api/ban", map[string]string{"ip": "203.0.113.5", "reason": "test"})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(mr.banned) != 1 || mr.banned[0] != "203.0.113.5" {
		t.Errorf("responder.Ban not called: %v", mr.banned)
	}
	if len(ms.bannedIPs) != 1 || ms.bannedIPs[0] != "203.0.113.5" {
		t.Errorf("store.BanIP not called: %v", ms.bannedIPs)
	}
}

func TestUnbanPost_Success(t *testing.T) {
	srv, ms, mr := newTestServer(t, true)
	w := postJSON(t, srv, "/api/unban", map[string]string{"ip": "203.0.113.5"})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(mr.unbanned) != 1 || mr.unbanned[0] != "203.0.113.5" {
		t.Errorf("responder.Unban not called: %v", mr.unbanned)
	}
	if len(ms.unbannedIPs) != 1 || ms.unbannedIPs[0] != "203.0.113.5" {
		t.Errorf("store.UnbanIP not called: %v", ms.unbannedIPs)
	}
}

func TestHealth_ResponderField(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("health: %d", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["responder_enabled"] != true {
		t.Errorf("responder_enabled: %v", resp["responder_enabled"])
	}
	if resp["responder_backend"] != "mock" {
		t.Errorf("responder_backend: %v", resp["responder_backend"])
	}
}

func TestBanPost_IPv4MappedSelfLockout(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	b, _ := json.Marshal(map[string]string{"ip": "203.0.113.99"})
	req := httptest.NewRequest(http.MethodPost, "/api/ban", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// Simulate dual-stack connection: RemoteAddr is IPv4-mapped IPv6
	req.RemoteAddr = "[::ffff:203.0.113.99]:12345"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for IPv4-mapped self-lockout, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUnbanNotRateLimited(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	// Exhaust the ban rate limiter by banning many distinct IPs quickly.
	for i := 0; i < 25; i++ {
		postJSON(t, srv, "/api/ban", map[string]string{"ip": fmt.Sprintf("203.0.%d.%d", i/256, i%256)})
	}
	// Unban should never be throttled.
	w := postJSON(t, srv, "/api/unban", map[string]string{"ip": "203.0.113.5"})
	if w.Code == http.StatusTooManyRequests {
		t.Error("unban must not be rate-limited, got 429")
	}
}

func newAuthServer(t *testing.T) *api.Server {
	t.Helper()
	cfg := &config.Config{
		Listen:      "127.0.0.1:0",
		AuthEnabled: true,
		AuthUser:    "admin",
		AuthPass:    "secret",
		IgnoreIPs:   []string{"127.0.0.0/8"},
	}
	ms := &mockStore{}
	srv := api.New(cfg, ms, "test")
	al, _ := responder.ParseAllowlist(cfg.IgnoreIPs)
	srv.SetResponder(responder.NoopResponder{}, al)
	return srv
}

func TestBasicAuth_NoCredentials(t *testing.T) {
	srv := newAuthServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestBasicAuth_WrongCredentials(t *testing.T) {
	srv := newAuthServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.SetBasicAuth("admin", "wrong")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestBasicAuth_Correct(t *testing.T) {
	srv := newAuthServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBasicAuth_HealthExempt(t *testing.T) {
	srv := newAuthServer(t)
	for _, path := range []string{"/api/health", "/api/health/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s must be exempt from auth, got %d", path, w.Code)
		}
	}
}

func TestMetrics(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"logfort_build_info",
		"logfort_lines_parsed_total",
		"logfort_lines_unparsed_total",
		"logfort_bans_active 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q:\n%s", want, body)
		}
	}
}

func TestEventsCSV(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/events.csv?type=failed_password", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("csv: %d — %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type: %q", ct)
	}
	if !strings.HasPrefix(w.Body.String(), "ts,ip,event_type") {
		t.Errorf("missing CSV header: %q", w.Body.String())
	}
}

func TestStats_InvalidWindow(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/stats?window=13x", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid window, got %d", w.Code)
	}
}

func TestNotifyTest_NotConfigured(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := postJSON(t, srv, "/api/notify/test", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 when no notifiers configured, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
}

// avoid unused import
var _ = time.Now

// --- fail2ban settings ---

func TestSettings_F2BOutOfRange(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := postJSON(t, srv, "/api/settings", map[string]any{"f2b_maxretry": 0})
	if w.Code != http.StatusBadRequest {
		t.Errorf("f2b_maxretry=0: got %d want 400", w.Code)
	}
	w = postJSON(t, srv, "/api/settings", map[string]any{"f2b_bantime_secs": 10})
	if w.Code != http.StatusBadRequest {
		t.Errorf("f2b_bantime_secs=10: got %d want 400", w.Code)
	}
}

func TestSettings_F2BUnavailable(t *testing.T) {
	// No F2B manager wired → applying jail settings must fail loudly with 502,
	// not pretend to save.
	srv, ms, _ := newTestServer(t, false)
	w := postJSON(t, srv, "/api/settings", map[string]any{"f2b_maxretry": 5})
	if w.Code != http.StatusBadGateway {
		t.Errorf("got %d want 502, body: %s", w.Code, w.Body.String())
	}
	if _, ok := ms.saved["f2b.maxretry"]; ok {
		t.Error("failed apply must not persist f2b.maxretry to the DB")
	}
}

func TestGetSettings_EnvLockedAndF2B(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	srv.SetEnvNotifyConfig(config.Config{NotifyTelegramToken: "env-token"})

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	var resp struct {
		EnvLocked []string       `json:"env_locked"`
		F2B       map[string]any `json:"f2b"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, f := range resp.EnvLocked {
		if f == "telegram_token" {
			found = true
		}
	}
	if !found {
		t.Errorf("env_locked must contain telegram_token, got %v", resp.EnvLocked)
	}
	if resp.F2B == nil {
		t.Fatal("f2b block missing from settings response")
	}
	if avail, _ := resp.F2B["available"].(bool); avail {
		t.Error("f2b.available must be false without a manager")
	}
}

func TestSettings_EnvPinnedFieldNotSaved(t *testing.T) {
	srv, ms, _ := newTestServer(t, false)
	srv.SetEnvNotifyConfig(config.Config{NotifyTelegramToken: "env-token"})

	w := postJSON(t, srv, "/api/settings", map[string]any{
		"telegram_token": "ui-token", "retention_days": 30,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, body: %s", w.Code, w.Body.String())
	}
	if _, ok := ms.saved["notify.telegram.token"]; ok {
		t.Error("env-pinned telegram token must not be written to the DB")
	}
	if ms.saved["general.retention_days"] != "30" {
		t.Errorf("retention_days must still be saved, got %v", ms.saved)
	}
}
