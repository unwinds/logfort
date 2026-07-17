package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unwinds/logfort/internal/hostinfo"
)

// getReq drives a GET request through the server's handler stack and returns the
// recorded response.
func getReq(t *testing.T, srv http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestHandleBans_JSON(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := getReq(t, srv, "/api/bans")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		Bans []any `json:"bans"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Bans == nil {
		t.Error("bans should serialize as [] not null")
	}
}

func TestHandleBansCSV(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := getReq(t, srv, "/api/bans.csv")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Errorf("content-type = %q, want text/csv", ct)
	}
	if !strings.HasPrefix(w.Body.String(), "ip,jail,banned_at") {
		t.Errorf("unexpected CSV header: %q", firstLine(w.Body.String()))
	}
}

func TestHandleEventsCSV(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := getReq(t, srv, "/api/events.csv")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Errorf("content-type = %q, want text/csv", ct)
	}
}

func TestHandleMap(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := getReq(t, srv, "/api/map?window=24h")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		Points []any `json:"points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Points == nil {
		t.Error("points should serialize as [] not null")
	}
}

func TestHandleMap_InvalidWindow(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := getReq(t, srv, "/api/map?window=bogus")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleVitals_Unavailable(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	w := getReq(t, srv, "/api/vitals")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body struct {
		Available bool  `json:"available"`
		Ports     []int `json:"ports"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Available {
		t.Error("available should be false without a vitals func")
	}
	if body.Ports == nil {
		t.Error("ports should serialize as [] not null")
	}
}

func TestHandleVitals_Available(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	srv.SetVitalsFunc(func() hostinfo.Snapshot {
		return hostinfo.Snapshot{Available: true, CPUPercent: 42}
	})
	w := getReq(t, srv, "/api/vitals")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body struct {
		Available  bool    `json:"available"`
		CPUPercent float64 `json:"cpu_percent"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Available || body.CPUPercent != 42 {
		t.Errorf("vitals = %+v, want available with cpu 42", body)
	}
}

func TestHandleIPInfo(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	w := getReq(t, srv, "/api/ip?ip=203.0.113.5")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		Info struct {
			IP string `json:"ip"`
		} `json:"info"`
		ResponderEnabled bool `json:"responder_enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Info.IP != "203.0.113.5" {
		t.Errorf("info.ip = %q, want 203.0.113.5", body.Info.IP)
	}
	if !body.ResponderEnabled {
		t.Error("responder_enabled should be true")
	}
}

func TestHandleIPInfo_BadIP(t *testing.T) {
	srv, _, _ := newTestServer(t, false)
	for _, path := range []string{"/api/ip?ip=not-an-ip", "/api/ip"} {
		w := getReq(t, srv, path)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET %s: status = %d, want 400", path, w.Code)
		}
	}
}

func TestHandleGetSystem(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	w := getReq(t, srv, "/api/system")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var body struct {
		ResponderBackend string `json:"responder_backend"`
		ResponderEnabled bool   `json:"responder_enabled"`
		AuthEnabled      bool   `json:"auth_enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ResponderBackend != "mock" {
		t.Errorf("responder_backend = %q, want mock", body.ResponderBackend)
	}
	if !body.ResponderEnabled {
		t.Error("responder_enabled should be true")
	}
	if body.AuthEnabled {
		t.Error("auth_enabled should be false")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
