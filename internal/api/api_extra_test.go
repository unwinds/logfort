package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func getPath(t *testing.T, srv http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "203.0.113.99:12345"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestHealth_DBProbe(t *testing.T) {
	srv, ms, _ := newTestServer(t, false)

	w := getPath(t, srv, "/api/health")
	if w.Code != http.StatusOK {
		t.Fatalf("healthy DB: want 200, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["db_ok"] != true {
		t.Errorf("db_ok: want true, got %v", resp["db_ok"])
	}

	ms.pingErr = errors.New("database is locked")
	w = getPath(t, srv, "/api/health")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("broken DB: want 503, got %d", w.Code)
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["db_ok"] != false || resp["status"] != "degraded" {
		t.Errorf("broken DB: db_ok=%v status=%v", resp["db_ok"], resp["status"])
	}
}

func TestBackup_StreamsSnapshot(t *testing.T) {
	srv, _, _ := newTestServer(t, false)

	w := getPath(t, srv, "/api/backup")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/vnd.sqlite3" {
		t.Errorf("Content-Type: %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "logfort-backup-") {
		t.Errorf("Content-Disposition: %q", cd)
	}
	if !strings.HasPrefix(w.Body.String(), "SQLite format 3") {
		t.Errorf("body must be the snapshot content, got %q", w.Body.String()[:min(32, w.Body.Len())])
	}
}

func TestBansCSV(t *testing.T) {
	srv, _, _ := newTestServer(t, false)

	w := getPath(t, srv, "/api/bans.csv")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type: %q", ct)
	}
	if !strings.HasPrefix(w.Body.String(), "ip,jail,banned_at") {
		t.Errorf("CSV header missing, got: %q", w.Body.String())
	}
}

func TestSettings_IgnoreIPs(t *testing.T) {
	srv, ms, _ := newTestServer(t, true)

	// Invalid entry → 400, nothing saved.
	w := postJSON(t, srv, "/api/settings", map[string]any{"ignore_ips": "1.2.3.4, not-an-ip"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid entry: want 400, got %d: %s", w.Code, w.Body.String())
	}
	if len(ms.saved) != 0 {
		t.Errorf("nothing must be saved on validation failure, got %v", ms.saved)
	}

	// Valid entries → saved and immediately effective for ban checks.
	w = postJSON(t, srv, "/api/settings", map[string]any{"ignore_ips": "203.0.113.7, 198.51.100.0/24"})
	if w.Code != http.StatusOK {
		t.Fatalf("valid entries: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := ms.saved["security.ignore_ips"]; got != "203.0.113.7,198.51.100.0/24" {
		t.Errorf("saved value: %q", got)
	}

	// The freshly allowlisted IP can no longer be banned.
	w = postJSON(t, srv, "/api/ban", map[string]string{"ip": "203.0.113.7"})
	if w.Code != http.StatusBadRequest {
		t.Errorf("banning an allowlisted IP: want 400, got %d: %s", w.Code, w.Body.String())
	}

	// GET must round-trip the extra entries and expose the base list.
	w = getPath(t, srv, "/api/settings")
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if got, _ := resp["ignore_ips"].(string); got != "203.0.113.7, 198.51.100.0/24" {
		t.Errorf("ignore_ips: %q", got)
	}
	base, _ := resp["ignore_ips_base"].([]any)
	if len(base) != 2 {
		t.Errorf("ignore_ips_base: %v", resp["ignore_ips_base"])
	}
}

func TestSettings_NewNotifierFields(t *testing.T) {
	srv, ms, _ := newTestServer(t, false)

	w := postJSON(t, srv, "/api/settings", map[string]any{
		"slack_url":    "https://hooks.slack.com/services/X",
		"ntfy_url":     "https://ntfy.sh/topic",
		"ntfy_token":   "tk",
		"gotify_url":   "https://gotify.example.com",
		"gotify_token": "app",
		"smtp_host":    "smtp.example.com:587",
		"smtp_from":    "logfort@example.com",
		"smtp_to":      "admin@example.com",
		"rules":        "ban",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	for key, want := range map[string]string{
		"notify.slack.url":    "https://hooks.slack.com/services/X",
		"notify.ntfy.url":     "https://ntfy.sh/topic",
		"notify.ntfy.token":   "tk",
		"notify.gotify.url":   "https://gotify.example.com",
		"notify.gotify.token": "app",
		"notify.smtp.host":    "smtp.example.com:587",
		"notify.smtp.from":    "logfort@example.com",
		"notify.smtp.to":      "admin@example.com",
		"notify.rules":        "ban",
	} {
		if got := ms.saved[key]; got != want {
			t.Errorf("saved[%s] = %q, want %q", key, got, want)
		}
	}

	// GET must return the values back.
	w = getPath(t, srv, "/api/settings")
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["slack_url"] != "https://hooks.slack.com/services/X" {
		t.Errorf("slack_url: %v", resp["slack_url"])
	}
	if resp["smtp_host"] != "smtp.example.com:587" {
		t.Errorf("smtp_host: %v", resp["smtp_host"])
	}
}

func TestSettings_NonStringNotifyFieldRejected(t *testing.T) {
	srv, ms, _ := newTestServer(t, false)

	w := postJSON(t, srv, "/api/settings", map[string]any{"slack_url": 12345})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-string field, got %d", w.Code)
	}
	if len(ms.saved) != 0 {
		t.Errorf("nothing must be saved, got %v", ms.saved)
	}
}
