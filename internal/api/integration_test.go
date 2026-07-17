package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unwinds/logfort/internal/api"
	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/ingest"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/responder"
	"github.com/unwinds/logfort/internal/store"
)

// scriptedSource emits a fixed set of lines then returns (no blocking), so the
// pipeline drains and Run returns once every line has been processed.
type scriptedSource struct{ lines []string }

func (s *scriptedSource) Info() ingest.SourceInfo {
	return ingest.SourceInfo{Kind: "fake", Target: "smoke"}
}

func (s *scriptedSource) Start(ctx context.Context, out chan<- string) error {
	for _, l := range s.lines {
		select {
		case out <- l:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// TestSmoke_EndToEnd wires the real store, ingest pipeline and API server the
// same way main.go does, feeds raw log lines through the parser, and verifies
// the data surfaces on the HTTP API. It is a boot smoke test for the full
// ingest → parse → store → API path against a live net/http server.
func TestSmoke_EndToEnd(t *testing.T) {
	const (
		sshFail   = "Jun 21 14:32:01 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2"
		sshAccept = "Jun 21 14:32:10 myhost sshd[12348]: Accepted publickey for bob from 192.0.2.11 port 22001 ssh2"
		garbage   = "this line is not a parseable log entry"
	)

	st, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer st.Close()

	cfg := &config.Config{Listen: "127.0.0.1:0", RetentionDays: 90}
	srv := api.New(cfg, st, "smoke-test")
	al, err := responder.ParseAllowlist(nil)
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	srv.SetResponder(responder.NoopResponder{}, al)

	src := &scriptedSource{lines: []string{sshFail, sshAccept, garbage}}
	pipeline := ingest.NewPipeline([]ingest.Source{src}, parse.ParseLine, st)
	srv.SetCounterFunc(pipeline.Counters)
	srv.SetSourceStatusFunc(pipeline.SourceStatuses)
	// Same publish fan-out main.go wires; all but PublishEvent are no-ops with
	// this config (nil dispatcher, auto-ban off, no blocklist), which exercises
	// their guard clauses.
	pipeline.SetPublishHook(func(ev *parse.Event) {
		srv.PublishEvent(ev)
		srv.NotifyEvent(ev)
		srv.AutoBanEvent(ev)
		srv.ThreatBanEvent(ev)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pipeline.Run(ctx); err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	ts := httptest.NewServer(srv)
	defer ts.Close()

	// --- /api/health ---
	var health struct {
		Status    string `json:"status"`
		Version   string `json:"version"`
		DBOk      bool   `json:"db_ok"`
		SourcesOk bool   `json:"sources_ok"`
		Parsed    int64  `json:"parsed_total"`
		Unparsed  int64  `json:"unparsed_total"`
	}
	getJSON(t, ts.URL+"/api/health", &health)
	if health.Status != "ok" || !health.DBOk || !health.SourcesOk {
		t.Errorf("health not ok: %+v", health)
	}
	if health.Version != "smoke-test" {
		t.Errorf("version = %q, want smoke-test", health.Version)
	}
	if health.Parsed != 2 {
		t.Errorf("parsed_total = %d, want 2", health.Parsed)
	}
	if health.Unparsed != 1 {
		t.Errorf("unparsed_total = %d, want 1", health.Unparsed)
	}

	// --- /api/events (no time filter → date-independent) ---
	var ev struct {
		Events []struct {
			IP        string `json:"ip"`
			EventType string `json:"event_type"`
		} `json:"events"`
		Total int64 `json:"total"`
	}
	getJSON(t, ts.URL+"/api/events", &ev)
	if ev.Total != 2 {
		t.Fatalf("events total = %d, want 2 (%+v)", ev.Total, ev.Events)
	}
	var sawFail, sawAccept bool
	for _, e := range ev.Events {
		switch e.EventType {
		case "failed_password":
			sawFail = true
			if e.IP != "203.0.113.5" {
				t.Errorf("failed_password IP = %q, want 203.0.113.5", e.IP)
			}
		case "accepted":
			sawAccept = true
		}
	}
	if !sawFail || !sawAccept {
		t.Errorf("missing events: failed=%v accepted=%v", sawFail, sawAccept)
	}

	// --- /api/stats?window=all (since=0 → date-independent) ---
	var stats struct {
		Failed     int64 `json:"failed"`
		Accepted   int64 `json:"accepted"`
		BucketSecs int64 `json:"bucket_secs"`
	}
	getJSON(t, ts.URL+"/api/stats?window=all", &stats)
	if stats.Failed < 1 {
		t.Errorf("stats.failed = %d, want >=1", stats.Failed)
	}
	if stats.Accepted < 1 {
		t.Errorf("stats.accepted = %d, want >=1", stats.Accepted)
	}
	if stats.BucketSecs == 0 {
		t.Error("stats.bucket_secs = 0, want non-zero")
	}
}

func getJSON(t *testing.T, url string, dst any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}
