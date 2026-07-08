package api

import (
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/f2b"
	"github.com/unwinds/logfort/internal/ingest"
	"github.com/unwinds/logfort/internal/notify"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/responder"
	"github.com/unwinds/logfort/internal/store"
	webui "github.com/unwinds/logfort/web"
)

// Server holds API dependencies and implements http.Handler.
type Server struct {
	cfg             *config.Config
	envCfg          config.Config // notify fields as loaded from env vars (pre-DB-overlay); gates UI writes
	cfgMu           sync.RWMutex  // protects runtime-mutable notify/autoban/retention fields of cfg
	store           store.Store
	mux             *http.ServeMux
	handler         http.Handler // pre-built: mux wrapped with basicAuth when auth is enabled
	hub             *Hub
	version         string
	startTS         time.Time
	parsedFn        func() (int64, int64)
	responder       responder.Responder
	allowlist       *responder.Allowlist
	banLim          *rateLimiter // limits ban requests only; unban is not throttled
	notifyMu        sync.RWMutex
	notifyFn        func(*parse.Event)
	notifyDisp      *notify.Dispatcher // tracked for Stop() on replacement
	geoIPEnabled    bool
	asnEnabled      bool
	f2bMgr          *f2b.Manager                 // nil when fail2ban integration is unavailable
	sourcesFn       func() []ingest.SourceStatus // pipeline source health for /api/health
	autoBanCooldown sync.Map                     // IP string → time.Time; prevents duplicate bans within window
	autoBanSem      chan struct{}                // limits concurrent auto-ban background goroutines
	statsCache      sync.Map                     // "stats:<window>" / "map:<window>" → statsCacheEntry
	shutCtx         context.Context
	shutCancel      context.CancelFunc
}

// New creates and configures the HTTP server.
func New(cfg *config.Config, st store.Store, version string) *Server {
	shutCtx, shutCancel := context.WithCancel(context.Background())
	s := &Server{
		cfg:        cfg,
		store:      st,
		version:    version,
		startTS:    time.Now(),
		mux:        http.NewServeMux(),
		hub:        newHub(),
		responder:  responder.NoopResponder{},
		banLim:     newRateLimiter(10, 20), // 10 req/s burst 20; unban is never throttled
		autoBanSem: make(chan struct{}, 100),
		shutCtx:    shutCtx,
		shutCancel: shutCancel,
	}
	s.routes()
	if cfg.AuthEnabled {
		s.handler = s.basicAuth(s.mux)
	} else {
		s.handler = s.mux
	}
	s.handler = securityHeaders(s.handler)
	return s
}

// SetResponder wires an active responder and its allowlist into the server.
func (s *Server) SetResponder(r responder.Responder, al *responder.Allowlist) {
	s.responder = r
	s.allowlist = al
}

// SetGeoIPEnabled records whether a GeoIP database was successfully loaded.
func (s *Server) SetGeoIPEnabled(v bool) { s.geoIPEnabled = v }

// SetASNEnabled records whether an ASN database was successfully loaded.
func (s *Server) SetASNEnabled(v bool) { s.asnEnabled = v }

// SetF2BManager wires the fail2ban jail manager used by the settings API.
// Call with nil (or not at all) when fail2ban integration is unavailable.
func (s *Server) SetF2BManager(m *f2b.Manager) { s.f2bMgr = m }

// SetSourceStatusFunc wires the pipeline's per-source health snapshot into
// /api/health.
func (s *Server) SetSourceStatusFunc(fn func() []ingest.SourceStatus) { s.sourcesFn = fn }

// SetEnvNotifyConfig records which notify fields were set by env vars.
// Fields non-empty in c will not be overridden at runtime by POST /api/settings.
func (s *Server) SetEnvNotifyConfig(c config.Config) {
	s.envCfg = c
}

// SetDispatcher wires a notify dispatcher, stopping the previous one.
// Thread-safe; can be called at runtime. Accepts nil to disable notifications.
func (s *Server) SetDispatcher(d *notify.Dispatcher) {
	s.swapDispatcher(d)
}

// SetNotifyFunc wires a raw notification callback. Thread-safe; can be called at runtime.
// Does not stop any previous Dispatcher — use SetDispatcher when possible.
func (s *Server) SetNotifyFunc(fn func(*parse.Event)) {
	s.notifyMu.Lock()
	s.notifyFn = fn
	s.notifyMu.Unlock()
}

func (s *Server) swapDispatcher(d *notify.Dispatcher) {
	s.notifyMu.Lock()
	if s.notifyDisp != nil {
		s.notifyDisp.Stop()
	}
	s.notifyDisp = d
	if d != nil {
		s.notifyFn = d.Notify
	} else {
		s.notifyFn = nil
	}
	s.notifyMu.Unlock()
}

// NotifyEvent dispatches ev through the current notification callback.
// Safe to call from multiple goroutines and after SetNotifyFunc.
func (s *Server) NotifyEvent(ev *parse.Event) {
	s.notifyMu.RLock()
	fn := s.notifyFn
	s.notifyMu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// PublishEvent serialises a parsed event and broadcasts it to all SSE subscribers.
// Safe to call from multiple goroutines.
func (s *Server) PublishEvent(ev *parse.Event) {
	var lat, lon *float64
	if ev.Geo.Lat != 0 || ev.Geo.Lon != 0 {
		lat, lon = &ev.Geo.Lat, &ev.Geo.Lon
	}
	payload := map[string]any{
		"ts":          ev.TS.Unix(),
		"ip":          ev.IP,
		"event_type":  ev.EventType,
		"username":    ev.Username,
		"user_valid":  ev.UserValid,
		"auth_method": ev.AuthMethod,
		"port":        ev.Port,
		"source":      ev.Source,
		"country":     ev.Geo.Country,
		"city":        ev.Geo.City,
		"lat":         lat,
		"lon":         lon,
		"asn":         ev.Geo.ASN,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := make([]byte, 0, len(data)+8)
	msg = append(msg, "data: "...)
	msg = append(msg, data...)
	msg = append(msg, '\n', '\n')
	s.hub.publish(msg)
}

// Shutdown disconnects all SSE subscribers so that http.Server.Shutdown can
// drain remaining requests instead of waiting out its timeout on streams that
// would otherwise never end. Call it BEFORE http.Server.Shutdown.
func (s *Server) Shutdown() {
	s.hub.close()
}

// Close signals shutdown and closes the SSE hub. Call after the HTTP server has stopped.
func (s *Server) Close() {
	s.shutCancel()
	s.hub.close()
}

// SetCounterFunc wires the pipeline's parsed/unparsed counters into /api/health.
func (s *Server) SetCounterFunc(fn func() (int64, int64)) {
	s.parsedFn = fn
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// securityHeaders adds baseline hardening headers to every response.
// The CSP allows inline script/style because the dashboard is a single
// self-contained HTML file; it still blocks all external origins, which is
// the part that matters for a LAN-facing admin panel.
func securityHeaders(h http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		"connect-src 'self'; font-src 'self'; object-src 'none'; " +
		"base-uri 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("Content-Security-Policy", csp)
		h.ServeHTTP(w, r)
	})
}

// authFailureDelay slows down credential brute-forcing without keeping
// per-IP state (which an attacker could grow without bound).
const authFailureDelay = 300 * time.Millisecond

// basicAuth wraps h with HTTP Basic authentication, exempting /api/health
// so the Docker HEALTHCHECK works without credentials in the image.
func (s *Server) basicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" || r.URL.Path == "/api/health/" {
			h.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.AuthUser)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.AuthPass)) == 1
		if !ok || !userMatch || !passMatch {
			if ok {
				// Only delay actual credential attempts, not the initial
				// challenge round-trip every browser session starts with.
				select {
				case <-time.After(authFailureDelay):
				case <-r.Context().Done():
				}
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="logfort"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	// API endpoints.
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/events", s.handleEvents)
	s.mux.HandleFunc("GET /api/events.csv", s.handleEventsCSV)
	s.mux.HandleFunc("GET /api/bans", s.handleBans)
	s.mux.HandleFunc("GET /api/bans.csv", s.handleBansCSV)
	s.mux.HandleFunc("GET /api/map", s.handleMap)
	s.mux.HandleFunc("GET /api/stream", s.handleStream)
	s.mux.HandleFunc("GET /api/backup", s.handleBackup)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Write endpoints (require responder enabled).
	s.mux.HandleFunc("POST /api/ban", s.handleBanPost)
	s.mux.HandleFunc("POST /api/unban", s.handleUnbanPost)

	// Settings endpoints.
	s.mux.HandleFunc("GET /api/system", s.handleGetSystem)
	s.mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	s.mux.HandleFunc("POST /api/settings", s.handlePostSettings)
	s.mux.HandleFunc("POST /api/notify/test", s.handleNotifyTest)

	// Static frontend.
	distFS, err := fs.Sub(webui.FS, "dist")
	if err != nil {
		panic("webui FS: " + err.Error())
	}
	fileServer := http.FileServerFS(distFS)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: serve index.html for unknown paths.
		if _, err := fs.Stat(distFS, r.URL.Path[1:]); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var parsed, unparsed int64
	if s.parsedFn != nil {
		parsed, unparsed = s.parsedFn()
	}
	// End-to-end DB probe: a corrupted or locked-up database must flip the
	// Docker HEALTHCHECK (which curls this endpoint) to unhealthy.
	dbOK := true
	if err := s.store.Ping(r.Context()); err != nil {
		dbOK = false
		slog.Error("health: db probe failed", "err", err)
	}
	resp := map[string]any{
		"status":            "ok",
		"version":           s.version,
		"uptime_s":          int64(time.Since(s.startTS).Seconds()),
		"parsed_total":      parsed,
		"unparsed_total":    unparsed,
		"db_ok":             dbOK,
		"responder_enabled": s.cfg.ResponderEnabled,
		"responder_backend": s.responder.Name(),
	}
	if s.sourcesFn != nil {
		sources := s.sourcesFn()
		ok := true
		for _, src := range sources {
			if src.State == "error" {
				ok = false
				break
			}
		}
		resp["sources"] = sources
		resp["sources_ok"] = ok
	}
	status := http.StatusOK
	if !dbOK {
		resp["status"] = "degraded"
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

// statsCacheEntry is a cached /api/stats or /api/map payload.
type statsCacheEntry struct {
	payload any
	expires time.Time
}

// cacheTTLForWindow returns how long responses for a stats window may be
// served from cache. Long windows aggregate a large slice of the events table
// (months of data on a busy host) — dashboards auto-refreshing every few
// seconds would re-run those scans for identical results. Short windows stay
// uncached so the live dashboard reflects new events immediately.
func cacheTTLForWindow(window string) time.Duration {
	switch window {
	case "7d", "30d", "all":
		return 60 * time.Second
	}
	return 0
}

// cachedPayload returns a fresh cached payload for key, or nil.
func (s *Server) cachedPayload(key string) any {
	if v, ok := s.statsCache.Load(key); ok {
		if e := v.(statsCacheEntry); time.Now().Before(e.expires) {
			return e.payload
		}
		s.statsCache.Delete(key)
	}
	return nil
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}
	if !store.IsValidWindow(window) {
		writeError(w, http.StatusBadRequest, "invalid window; use 1h|6h|24h|7d|30d|all")
		return
	}
	ttl := cacheTTLForWindow(window)
	if ttl > 0 {
		if cached := s.cachedPayload("stats:" + window); cached != nil {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}
	st, err := s.store.GetStats(r.Context(), window)
	if err != nil {
		slog.Error("get stats", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ttl > 0 {
		s.statsCache.Store("stats:"+window, statsCacheEntry{payload: st, expires: time.Now().Add(ttl)})
	}
	writeJSON(w, http.StatusOK, st)
}

// eventQueryFromRequest builds a store.EventQuery from shared query params
// (limit, offset, type, ip, country, user, since, until) capped at maxLimit.
func eventQueryFromRequest(r *http.Request, defLimit, maxLimit int) store.EventQuery {
	q := store.EventQuery{
		Limit:     parseIntQuery(r, "limit", defLimit),
		Offset:    parseIntQuery(r, "offset", 0),
		EventType: r.URL.Query().Get("type"),
		IP:        r.URL.Query().Get("ip"),
		Country:   r.URL.Query().Get("country"),
		Username:  r.URL.Query().Get("user"),
	}
	if q.Limit < 1 {
		q.Limit = defLimit
	}
	if q.Limit > maxLimit {
		q.Limit = maxLimit
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if raw := r.URL.Query().Get("since"); raw != "" {
		if ts, err := strconv.ParseInt(raw, 10, 64); err == nil {
			t := time.Unix(ts, 0)
			q.Since = &t
		}
	}
	if raw := r.URL.Query().Get("until"); raw != "" {
		if ts, err := strconv.ParseInt(raw, 10, 64); err == nil {
			t := time.Unix(ts, 0)
			q.Until = &t
		}
	}
	return q
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := eventQueryFromRequest(r, 100, 1000)

	events, total, err := s.store.ListEvents(r.Context(), q)
	if err != nil {
		slog.Error("list events", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"total":  total,
		"limit":  q.Limit,
		"offset": q.Offset,
	})
}

// handleEventsCSV streams events matching the same filters as /api/events as
// a CSV download (up to 10 000 rows per request).
func (s *Server) handleEventsCSV(w http.ResponseWriter, r *http.Request) {
	q := eventQueryFromRequest(r, 10000, 10000)

	events, _, err := s.store.ListEvents(r.Context(), q)
	if err != nil {
		slog.Error("export events", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="logfort-events.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ts", "ip", "event_type", "username", "user_valid", "auth_method", "port", "source", "country", "city", "lat", "lon", "asn"})
	for _, e := range events {
		userValid := ""
		if e.UserValid != nil {
			userValid = strconv.FormatBool(*e.UserValid)
		}
		port := ""
		if e.Port != 0 {
			port = strconv.Itoa(e.Port)
		}
		lat, lon := "", ""
		if e.Lat != nil {
			lat = strconv.FormatFloat(*e.Lat, 'f', 4, 64)
		}
		if e.Lon != nil {
			lon = strconv.FormatFloat(*e.Lon, 'f', 4, 64)
		}
		_ = cw.Write([]string{
			time.Unix(e.TS, 0).UTC().Format(time.RFC3339),
			e.IP, e.EventType, csvCell(e.Username), userValid, e.AuthMethod,
			port, e.Source, csvCell(e.Country), csvCell(e.City), lat, lon, csvCell(e.ASN),
		})
	}
	cw.Flush()
}

// handleMetrics exposes counters in the Prometheus text exposition format.
// Hand-rolled to avoid pulling in the client library for five metrics.
// Subject to basic auth like the rest of the API (Prometheus supports
// basic_auth in scrape_configs).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var parsed, unparsed int64
	if s.parsedFn != nil {
		parsed, unparsed = s.parsedFn()
	}
	activeBans := int64(0)
	if bans, err := s.store.ListBans(r.Context(), true); err == nil {
		activeBans = int64(len(bans))
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP logfort_build_info Build information.\n# TYPE logfort_build_info gauge\nlogfort_build_info{version=%q} 1\n", s.version)
	fmt.Fprintf(w, "# HELP logfort_uptime_seconds Seconds since the process started.\n# TYPE logfort_uptime_seconds gauge\nlogfort_uptime_seconds %d\n", int64(time.Since(s.startTS).Seconds()))
	fmt.Fprintf(w, "# HELP logfort_lines_parsed_total Log lines parsed into events.\n# TYPE logfort_lines_parsed_total counter\nlogfort_lines_parsed_total %d\n", parsed)
	fmt.Fprintf(w, "# HELP logfort_lines_unparsed_total Log lines that matched no pattern.\n# TYPE logfort_lines_unparsed_total counter\nlogfort_lines_unparsed_total %d\n", unparsed)
	fmt.Fprintf(w, "# HELP logfort_bans_active Currently active bans.\n# TYPE logfort_bans_active gauge\nlogfort_bans_active %d\n", activeBans)
	fmt.Fprintf(w, "# HELP logfort_sse_clients Currently connected event-stream clients.\n# TYPE logfort_sse_clients gauge\nlogfort_sse_clients %d\n", s.hub.clientCount())
	if size := dbSizeBytes(s.cfg.DBPath); size > 0 {
		fmt.Fprintf(w, "# HELP logfort_db_size_bytes SQLite database file size.\n# TYPE logfort_db_size_bytes gauge\nlogfort_db_size_bytes %d\n", size)
	}
}

// dbSizeBytes returns the size of the database file, or 0 when it cannot be
// determined (e.g. :memory: databases in tests).
func dbSizeBytes(path string) int64 {
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return 0
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// handleBansCSV exports ban records as a CSV download.
func (s *Server) handleBansCSV(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") != "false"
	bans, err := s.store.ListBans(r.Context(), activeOnly)
	if err != nil {
		slog.Error("export bans", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="logfort-bans.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ip", "jail", "banned_at", "unbanned_at", "expires_at", "active", "source", "reason"})
	for _, b := range bans {
		unbannedAt := ""
		if b.UnbannedAt != nil {
			unbannedAt = time.Unix(*b.UnbannedAt, 0).UTC().Format(time.RFC3339)
		}
		expiresAt := ""
		if b.ExpiresAt != nil {
			expiresAt = time.Unix(*b.ExpiresAt, 0).UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			b.IP, csvCell(b.Jail),
			time.Unix(b.BannedAt, 0).UTC().Format(time.RFC3339),
			unbannedAt, expiresAt, strconv.FormatBool(b.Active), b.Source, csvCell(b.Reason),
		})
	}
	cw.Flush()
}

// handleBackup streams a consistent point-in-time snapshot of the SQLite
// database as a download. The snapshot is produced with VACUUM INTO, so it is
// safe while the pipeline keeps writing and is also defragmented for free.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	tmp, err := os.CreateTemp("", "logfort-backup-*.db")
	if err != nil {
		slog.Error("backup: temp file", "err", err)
		writeError(w, http.StatusInternalServerError, "backup failed")
		return
	}
	tmpPath := tmp.Name()
	tmp.Close()
	// VACUUM INTO refuses to overwrite; hand it a fresh path and make sure the
	// snapshot is cleaned up whatever happens below.
	os.Remove(tmpPath)
	defer os.Remove(tmpPath)

	if err := s.store.Backup(r.Context(), tmpPath); err != nil {
		slog.Error("backup", "err", err)
		writeError(w, http.StatusInternalServerError, "backup failed")
		return
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		slog.Error("backup: open snapshot", "err", err)
		writeError(w, http.StatusInternalServerError, "backup failed")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition",
		`attachment; filename="logfort-backup-`+time.Now().UTC().Format("20060102-150405")+`.db"`)
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	if _, err := io.Copy(w, f); err != nil {
		slog.Warn("backup: stream interrupted", "err", err)
	}
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") != "false"
	bans, err := s.store.ListBans(r.Context(), activeOnly)
	if err != nil {
		slog.Error("list bans", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bans": bans})
}

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}
	if !store.IsValidWindow(window) {
		writeError(w, http.StatusBadRequest, "invalid window; use 1h|6h|24h|7d|30d|all")
		return
	}
	ttl := cacheTTLForWindow(window)
	if ttl > 0 {
		if cached := s.cachedPayload("map:" + window); cached != nil {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}
	points, err := s.store.GetMapPoints(r.Context(), window)
	if err != nil {
		slog.Error("map points", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if points == nil {
		points = []store.MapPoint{}
	}
	resp := map[string]any{"points": points}
	if s.cfg.HomeLat != nil && s.cfg.HomeLon != nil {
		resp["home_lat"] = *s.cfg.HomeLat
		resp["home_lon"] = *s.cfg.HomeLon
	}
	if ttl > 0 {
		s.statsCache.Store("map:"+window, statsCacheEntry{payload: resp, expires: time.Now().Add(ttl)})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// The server-wide WriteTimeout would otherwise kill this long-lived
	// stream; clear the per-connection write deadline for SSE only.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			_, _ = w.Write(msg)
			flusher.Flush()
		case <-ticker.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) handleBanPost(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ResponderEnabled {
		writeError(w, http.StatusForbidden, "responder is disabled; set LOGFORT_RESPONDER_ENABLED=true to enable")
		return
	}
	if !s.banLim.Allow() {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var req struct {
		IP           string `json:"ip"`
		Reason       string `json:"reason"`
		DurationSecs int64  `json:"duration_secs"` // 0 = permanent
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	req.Reason = strings.TrimSpace(req.Reason)

	if !responder.IsValid(req.IP) {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	if req.DurationSecs < 0 || req.DurationSecs > maxBanDurationSecs {
		writeError(w, http.StatusBadRequest, "duration_secs must be between 0 (permanent) and 31536000 (365 days)")
		return
	}
	// Anti-self-lockout: compare against the originating client IP, which
	// accounts for IPv4-mapped IPv6 and for a local reverse proxy in front.
	remoteIP := clientIP(r)
	if remoteIP == normalizeIP(req.IP) {
		writeError(w, http.StatusBadRequest, "cannot ban your own IP address")
		return
	}
	if responder.IsPrivate(req.IP) {
		writeError(w, http.StatusBadRequest, "cannot ban private/loopback IP addresses")
		return
	}
	if s.allowlist != nil && s.allowlist.Contains(req.IP) {
		writeError(w, http.StatusBadRequest, "IP is in the allowlist and cannot be banned")
		return
	}

	var expiresAt int64
	if req.DurationSecs > 0 {
		expiresAt = time.Now().Add(time.Duration(req.DurationSecs) * time.Second).Unix()
	}
	// Record in store first; roll back if the firewall operation fails.
	if err := s.store.BanIP(r.Context(), req.IP, s.responder.Name(), req.Reason, expiresAt); err != nil {
		slog.Error("store ban", "ip", req.IP, "err", err)
		writeError(w, http.StatusInternalServerError, "failed to record ban")
		return
	}
	if err := s.responder.Ban(r.Context(), req.IP); err != nil {
		if rbErr := s.store.UnbanIP(r.Context(), req.IP); rbErr != nil {
			slog.Error("rollback store after failed ban", "ip", req.IP, "err", rbErr)
		}
		slog.Error("ban failed", "ip", req.IP, "err", err)
		writeError(w, http.StatusInternalServerError, "ban failed: "+err.Error())
		return
	}
	slog.Info("manual ban", "ip", req.IP, "reason", req.Reason, "remote", remoteIP, "backend", s.responder.Name())
	banEv := &parse.Event{
		TS:        time.Now().UTC(),
		IP:        req.IP,
		EventType: "ban",
		Source:    "manual",
	}
	// Record in the events feed too, so manual bans show up in the timeline
	// alongside fail2ban's. The bans-table mirror inside InsertEvent is a
	// no-op here (BanIP above already created the active row).
	if err := s.store.InsertEvent(r.Context(), banEv); err != nil && !errors.Is(err, store.ErrDuplicate) {
		slog.Warn("record manual ban event", "ip", req.IP, "err", err)
	}
	s.PublishEvent(banEv)
	s.NotifyEvent(banEv)
	writeJSON(w, http.StatusOK, map[string]string{"status": "banned", "ip": req.IP})
}

func (s *Server) handleUnbanPost(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ResponderEnabled {
		writeError(w, http.StatusForbidden, "responder is disabled; set LOGFORT_RESPONDER_ENABLED=true to enable")
		return
	}
	// Unban is not rate-limited: blocking emergency unbans would be dangerous.

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.IP = strings.TrimSpace(req.IP)

	if !responder.IsValid(req.IP) {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	if err := s.responder.Unban(r.Context(), req.IP); err != nil {
		slog.Error("unban failed", "ip", req.IP, "err", err)
		writeError(w, http.StatusInternalServerError, "unban failed: "+err.Error())
		return
	}
	if err := s.store.UnbanIP(r.Context(), req.IP); err != nil {
		slog.Error("store unban", "ip", req.IP, "err", err)
		writeError(w, http.StatusInternalServerError, "failed to record unban")
		return
	}
	slog.Info("manual unban", "ip", req.IP, "remote", clientIP(r), "backend", s.responder.Name())
	unbanEv := &parse.Event{
		TS:        time.Now().UTC(),
		IP:        req.IP,
		EventType: "unban",
		Source:    "manual",
	}
	if err := s.store.InsertEvent(r.Context(), unbanEv); err != nil && !errors.Is(err, store.ErrDuplicate) {
		slog.Warn("record manual unban event", "ip", req.IP, "err", err)
	}
	s.PublishEvent(unbanEv)
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": req.IP})
}

// --- settings handlers ---

// notifySettingJSONKeys maps the JSON field names used by GET/POST
// /api/settings to the DB settings keys of config.NotifySettingKeys. One
// table drives reading, writing, and env-lock reporting so the three can
// never disagree.
var notifySettingJSONKeys = map[string]string{
	"telegram_token":   "notify.telegram.token",
	"telegram_chat_id": "notify.telegram.chat_id",
	"discord_url":      "notify.discord.url",
	"webhook_url":      "notify.webhook.url",
	"slack_url":        "notify.slack.url",
	"ntfy_url":         "notify.ntfy.url",
	"ntfy_token":       "notify.ntfy.token",
	"gotify_url":       "notify.gotify.url",
	"gotify_token":     "notify.gotify.token",
	"smtp_host":        "notify.smtp.host",
	"smtp_user":        "notify.smtp.user",
	"smtp_pass":        "notify.smtp.pass",
	"smtp_from":        "notify.smtp.from",
	"smtp_to":          "notify.smtp.to",
}

func (s *Server) handleGetSystem(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"backend":           s.cfg.Backend,
		"log_paths":         s.cfg.LogPaths,
		"fail2ban_log":      s.cfg.Fail2BanLog,
		"journald_unit":     s.cfg.JournaldUnit,
		"geoip_enabled":     s.geoIPEnabled,
		"asn_enabled":       s.asnEnabled,
		"responder_enabled": s.cfg.ResponderEnabled,
		"responder_backend": s.responder.Name(),
		"fail2ban_jail":     s.cfg.Fail2BanJail,
		"f2b_available":     s.f2bMgr != nil && s.f2bMgr.Available(),
		"auth_enabled":      s.cfg.AuthEnabled,
		"listen":            s.cfg.Listen,
		"db_path":           s.cfg.DBPath,
		"db_size_bytes":     dbSizeBytes(s.cfg.DBPath),
	})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	resp := map[string]any{
		"rules":             strings.Join(s.cfg.NotifyRules, ","),
		"retention_days":    s.cfg.RetentionDays,
		"autoban_enabled":      s.cfg.AutoBanEnabled,
		"autoban_threshold":    s.cfg.AutoBanThreshold,
		"autoban_window":       s.cfg.AutoBanWindow,
		"autoban_bantime_secs": s.cfg.AutoBanBanTime,
		"ignore_ips":        strings.Join(s.cfg.ExtraIgnoreIPs, ", "),
		"ignore_ips_base":   append([]string{}, s.cfg.IgnoreIPs...),
	}
	cfgKeys := s.cfg.NotifySettingKeys()
	for jsonKey, dbKey := range notifySettingJSONKeys {
		resp[jsonKey] = *cfgKeys[dbKey]
	}
	storedF2B := f2b.JailSettings{
		MaxRetry:     s.cfg.F2BMaxRetry,
		BanTimeSecs:  s.cfg.F2BBanTime,
		FindTimeSecs: s.cfg.F2BFindTime,
	}
	s.cfgMu.RUnlock()

	// Fields pinned by env vars cannot be changed at runtime — tell the UI so
	// it can disable those inputs instead of silently ignoring edits.
	locked := []string{}
	envKeys := s.envCfg.NotifySettingKeys()
	for jsonKey, dbKey := range notifySettingJSONKeys {
		if *envKeys[dbKey] != "" {
			locked = append(locked, jsonKey)
		}
	}
	if len(s.envCfg.NotifyRules) > 0 {
		locked = append(locked, "rules")
	}
	sort.Strings(locked)
	resp["env_locked"] = locked

	// fail2ban jail block: live values when the server is reachable (the
	// user should see what fail2ban actually enforces), stored values as a
	// fallback. Socket I/O happens outside cfgMu.
	f2bResp := map[string]any{"available": false, "jail": s.cfg.Fail2BanJail}
	if s.f2bMgr != nil && s.f2bMgr.Available() {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		live, err := s.f2bMgr.GetJail(ctx)
		cancel()
		if err == nil {
			f2bResp["available"] = true
			f2bResp["maxretry"] = live.MaxRetry
			f2bResp["bantime_secs"] = live.BanTimeSecs
			f2bResp["findtime_secs"] = live.FindTimeSecs
			f2bResp["managed"] = storedF2B.MaxRetry > 0 || storedF2B.BanTimeSecs > 0 || storedF2B.FindTimeSecs > 0
		} else {
			slog.Debug("f2b live read failed", "err", err)
			f2bResp["error"] = err.Error()
		}
	}
	resp["f2b"] = f2bResp

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePostSettings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}
	// Pointer fields: nil means "field not present in request → don't change".
	var req struct {
		Rules *string `json:"rules"`
		// General settings
		RetentionDays    *int    `json:"retention_days"`
		AutoBanEnabled   *bool   `json:"autoban_enabled"`
		AutoBanThreshold *int    `json:"autoban_threshold"`
		AutoBanWindow    *string `json:"autoban_window"`
		AutoBanBanTime   *int64  `json:"autoban_bantime_secs"` // 0 = permanent
		IgnoreIPs        *string `json:"ignore_ips"`
		// fail2ban jail tuning (applied via the fail2ban socket)
		F2BMaxRetry *int64 `json:"f2b_maxretry"`
		F2BBanTime  *int64 `json:"f2b_bantime_secs"`
		F2BFindTime *int64 `json:"f2b_findtime_secs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	// The plain-string notify channel fields are decoded through the raw
	// message so notifySettingJSONKeys is the single list of what exists.
	var rawFields map[string]json.RawMessage
	_ = json.Unmarshal(body, &rawFields) // syntax already validated above

	// Build the effective config: start from current, apply request values only
	// for fields not pinned by env vars.
	s.cfgMu.RLock()
	proposed := *s.cfg
	s.cfgMu.RUnlock()

	toSave := make(map[string]string)
	notifyChanged := false

	envKeys := s.envCfg.NotifySettingKeys()
	propKeys := proposed.NotifySettingKeys()
	for jsonKey, dbKey := range notifySettingJSONKeys {
		rawVal, present := rawFields[jsonKey]
		if !present {
			continue
		}
		var v string
		if err := json.Unmarshal(rawVal, &v); err != nil {
			writeError(w, http.StatusBadRequest, jsonKey+" must be a string")
			return
		}
		notifyChanged = true
		if *envKeys[dbKey] != "" {
			continue // env var pins this field; ignore the UI value
		}
		*propKeys[dbKey] = v
		toSave[dbKey] = v
	}
	if req.Rules != nil {
		notifyChanged = true
		if len(s.envCfg.NotifyRules) == 0 {
			proposed.NotifyRules = config.SplitList(*req.Rules)
			toSave["notify.rules"] = *req.Rules
		}
	}

	// General fields (no env pins; nil = skip).
	if req.RetentionDays != nil && *req.RetentionDays > 0 {
		proposed.RetentionDays = *req.RetentionDays
	}
	if req.AutoBanEnabled != nil {
		proposed.AutoBanEnabled = *req.AutoBanEnabled
	}
	if req.AutoBanThreshold != nil && *req.AutoBanThreshold > 0 {
		proposed.AutoBanThreshold = *req.AutoBanThreshold
	}
	if req.AutoBanWindow != nil {
		if _, err := time.ParseDuration(*req.AutoBanWindow); err != nil {
			writeError(w, http.StatusBadRequest, "invalid autoban_window: "+err.Error())
			return
		}
		proposed.AutoBanWindow = *req.AutoBanWindow
	}
	if req.AutoBanBanTime != nil {
		if *req.AutoBanBanTime < 0 || *req.AutoBanBanTime > maxBanDurationSecs {
			writeError(w, http.StatusBadRequest, "autoban_bantime_secs must be between 0 (permanent) and 31536000 (365 days)")
			return
		}
		proposed.AutoBanBanTime = *req.AutoBanBanTime
	}

	// Extra allowlist entries — validate every IP/CIDR before persisting.
	if req.IgnoreIPs != nil {
		entries := config.SplitList(*req.IgnoreIPs)
		if _, err := responder.ParseAllowlist(entries); err != nil {
			writeError(w, http.StatusBadRequest, "invalid ignore_ips: "+err.Error())
			return
		}
		proposed.ExtraIgnoreIPs = entries
		toSave["security.ignore_ips"] = strings.Join(entries, ",")
	}

	// fail2ban jail fields — validate ranges up front.
	f2bChanged := req.F2BMaxRetry != nil || req.F2BBanTime != nil || req.F2BFindTime != nil
	if req.F2BMaxRetry != nil {
		if *req.F2BMaxRetry < 1 || *req.F2BMaxRetry > 100 {
			writeError(w, http.StatusBadRequest, "f2b_maxretry must be between 1 and 100")
			return
		}
		proposed.F2BMaxRetry = *req.F2BMaxRetry
	}
	if req.F2BBanTime != nil {
		if *req.F2BBanTime < 60 || *req.F2BBanTime > 90*24*3600 {
			writeError(w, http.StatusBadRequest, "f2b_bantime_secs must be between 60 (1 min) and 7776000 (90 days)")
			return
		}
		proposed.F2BBanTime = *req.F2BBanTime
	}
	if req.F2BFindTime != nil {
		if *req.F2BFindTime < 60 || *req.F2BFindTime > 7*24*3600 {
			writeError(w, http.StatusBadRequest, "f2b_findtime_secs must be between 60 (1 min) and 604800 (7 days)")
			return
		}
		proposed.F2BFindTime = *req.F2BFindTime
	}

	// Validate notify config before touching the DB.
	d, err := notify.New(&proposed, s.store)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}

	// Apply fail2ban settings to the running server BEFORE persisting, so the
	// user gets a hard error (and no stale DB state) when fail2ban is
	// unreachable — "saved but not applied" is exactly the confusion this
	// feature exists to remove.
	if f2bChanged {
		if s.f2bMgr == nil || !s.f2bMgr.Available() {
			d.Stop()
			writeError(w, http.StatusBadGateway, "fail2ban is not reachable: the fail2ban socket is not mounted into the container (re-run install.sh and enable fail2ban integration)")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		applyErr := s.f2bMgr.SetJail(ctx, f2b.JailSettings{
			MaxRetry:     valOrZero(req.F2BMaxRetry),
			BanTimeSecs:  valOrZero(req.F2BBanTime),
			FindTimeSecs: valOrZero(req.F2BFindTime),
		})
		cancel()
		if applyErr != nil {
			d.Stop()
			writeError(w, http.StatusBadGateway, "failed to apply fail2ban settings: "+applyErr.Error())
			return
		}
	}

	// Persist all changed fields atomically in a single transaction.
	// Env-pinned notify fields were skipped above: the env var wins at
	// runtime, so writing a diverging DB value would only create a surprise
	// when the env var is later removed.
	if req.F2BMaxRetry != nil {
		toSave["f2b.maxretry"] = strconv.FormatInt(proposed.F2BMaxRetry, 10)
	}
	if req.F2BBanTime != nil {
		toSave["f2b.bantime"] = strconv.FormatInt(proposed.F2BBanTime, 10)
	}
	if req.F2BFindTime != nil {
		toSave["f2b.findtime"] = strconv.FormatInt(proposed.F2BFindTime, 10)
	}
	if req.RetentionDays != nil {
		toSave["general.retention_days"] = strconv.Itoa(proposed.RetentionDays)
	}
	if req.AutoBanEnabled != nil {
		if proposed.AutoBanEnabled {
			toSave["autoban.enabled"] = "true"
		} else {
			toSave["autoban.enabled"] = "false"
		}
	}
	if req.AutoBanThreshold != nil {
		toSave["autoban.threshold"] = strconv.Itoa(proposed.AutoBanThreshold)
	}
	if req.AutoBanWindow != nil {
		toSave["autoban.window"] = proposed.AutoBanWindow
	}
	if req.AutoBanBanTime != nil {
		toSave["autoban.bantime"] = strconv.FormatInt(proposed.AutoBanBanTime, 10)
	}
	if len(toSave) > 0 {
		if err := s.store.SetSettings(r.Context(), toSave); err != nil {
			slog.Error("save settings", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to save settings")
			return
		}
	}

	// Apply effective config to in-memory state.
	s.cfgMu.Lock()
	liveKeys := s.cfg.NotifySettingKeys()
	for dbKey, src := range proposed.NotifySettingKeys() {
		*liveKeys[dbKey] = *src
	}
	s.cfg.NotifyRules = proposed.NotifyRules
	s.cfg.RetentionDays = proposed.RetentionDays
	s.cfg.AutoBanEnabled = proposed.AutoBanEnabled
	s.cfg.AutoBanThreshold = proposed.AutoBanThreshold
	s.cfg.AutoBanWindow = proposed.AutoBanWindow
	s.cfg.AutoBanBanTime = proposed.AutoBanBanTime
	s.cfg.ExtraIgnoreIPs = proposed.ExtraIgnoreIPs
	s.cfg.F2BMaxRetry = proposed.F2BMaxRetry
	s.cfg.F2BBanTime = proposed.F2BBanTime
	s.cfg.F2BFindTime = proposed.F2BFindTime
	s.cfgMu.Unlock()

	// Update the live allowlist so new entries take effect immediately for
	// auto-ban and manual-ban checks (entries were validated above).
	if req.IgnoreIPs != nil && s.allowlist != nil {
		if err := s.allowlist.SetExtra(proposed.ExtraIgnoreIPs); err != nil {
			slog.Error("apply allowlist", "err", err)
		}
	}

	// Swap dispatcher only if notify fields were included in this request.
	if notifyChanged {
		s.swapDispatcher(d)
	} else {
		d.Stop() // nil-safe; discard the unused validation dispatcher
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	s.notifyMu.RLock()
	disp := s.notifyDisp
	hasNotifier := s.notifyFn != nil
	s.notifyMu.RUnlock()

	if disp != nil {
		// Send synchronously, bypassing rules, so the user gets real delivery
		// feedback instead of "sent" regardless of outcome.
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := disp.SendTest(ctx); err != nil {
			writeError(w, http.StatusBadGateway, "delivery failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
		return
	}
	if !hasNotifier {
		writeError(w, http.StatusBadRequest, "no notifiers configured — save settings first")
		return
	}
	// Fallback for a raw notify func (tests via SetNotifyFunc).
	s.NotifyEvent(&parse.Event{
		TS:        time.Now().UTC(),
		IP:        "203.0.113.1",
		EventType: "ban",
		Username:  "test",
		Source:    "logfort-test",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// AutoBanEvent checks whether ev's source IP has crossed the auto-ban threshold
// and, if so, bans it via the responder in a background goroutine.
func (s *Server) AutoBanEvent(ev *parse.Event) {
	s.cfgMu.RLock()
	enabled := s.cfg.AutoBanEnabled
	responderEnabled := s.cfg.ResponderEnabled
	threshold := s.cfg.AutoBanThreshold
	window := s.cfg.AutoBanWindow
	banTime := s.cfg.AutoBanBanTime
	s.cfgMu.RUnlock()

	if !enabled || !responderEnabled {
		return
	}
	// Only react to primary attempt events — the same set CountIPEvents
	// counts. Auxiliary lines (invalid_user, pam_failure, disconnect_preauth)
	// would trigger redundant threshold checks for the same attempt.
	switch ev.EventType {
	case "failed_password", "http_auth_fail", "mail_auth_fail", "max_auth":
	default:
		return
	}

	// Normalize to plain IPv4 so ::ffff:1.2.3.4 and 1.2.3.4 are treated identically.
	ip := normalizeIP(ev.IP)
	if ip == "" || responder.IsPrivate(ip) {
		return
	}
	if s.allowlist != nil && s.allowlist.Contains(ip) {
		return
	}

	dur, err := time.ParseDuration(window)
	if err != nil || threshold <= 0 {
		return
	}

	now := time.Now()
	// Atomically claim the cooldown slot. LoadOrStore ensures only one goroutine
	// proceeds when no prior entry exists; if an entry exists and is not expired,
	// skip. On expiry, overwrite the stale entry and proceed.
	if prev, loaded := s.autoBanCooldown.LoadOrStore(ip, now); loaded {
		if now.Sub(prev.(time.Time)) < dur {
			return
		}
		s.autoBanCooldown.Store(ip, now)
	}

	// Semaphore: cap concurrent background goroutines to bound resource use during bursts.
	select {
	case s.autoBanSem <- struct{}{}:
	default:
		// At capacity; clear the cooldown we just set so this IP can retry on the next event.
		s.autoBanCooldown.Delete(ip)
		return
	}
	go func() {
		defer func() { <-s.autoBanSem }()
		s.autoBanBackground(ip, threshold, dur, banTime, now)
	}()
}

func (s *Server) autoBanBackground(ip string, threshold int, dur time.Duration, banTime int64, now time.Time) {
	// Respect server shutdown; cap individual ban operations at 30s.
	ctx, cancel := context.WithTimeout(s.shutCtx, 30*time.Second)
	defer cancel()

	count, err := s.store.CountIPEvents(ctx, ip, now.Add(-dur))
	if err != nil {
		slog.Warn("auto-ban count", "ip", ip, "err", err)
		s.autoBanCooldown.Delete(ip) // allow retry after transient DB error
		return
	}
	if count < int64(threshold) {
		// Threshold not reached; clear cooldown so the next event rechecks.
		s.autoBanCooldown.Delete(ip)
		return
	}

	var expiresAt int64
	if banTime > 0 {
		expiresAt = now.Add(time.Duration(banTime) * time.Second).Unix()
	}
	if err := s.store.BanIP(ctx, ip, s.responder.Name(), "auto-ban", expiresAt); err != nil {
		// BanIP uses INSERT WHERE NOT EXISTS: nil error means 0 rows (already banned).
		// Any non-nil error here is a real DB failure.
		slog.Error("auto-ban store", "ip", ip, "err", err)
		s.autoBanCooldown.Delete(ip) // allow retry
		return
	}
	if err := s.responder.Ban(ctx, ip); err != nil {
		if rbErr := s.store.UnbanIP(ctx, ip); rbErr != nil {
			slog.Error("auto-ban rollback", "ip", ip, "err", rbErr)
		}
		slog.Error("auto-ban responder", "ip", ip, "err", err)
		s.autoBanCooldown.Delete(ip) // allow retry after transient firewall error
		return
	}

	slog.Info("auto-ban", "ip", ip, "count", count, "window", dur, "backend", s.responder.Name())

	banEv := &parse.Event{
		TS:        time.Now().UTC(),
		IP:        ip,
		EventType: "ban",
		Source:    "auto-ban",
	}
	if err := s.store.InsertEvent(ctx, banEv); err != nil && !errors.Is(err, store.ErrDuplicate) {
		slog.Warn("record auto-ban event", "ip", ip, "err", err)
	}
	s.PublishEvent(banEv)
	s.NotifyEvent(banEv)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// csvCell neutralises spreadsheet formula injection: attacker-controlled
// values (SSH usernames) that start with =, +, -, @ or a control character
// would otherwise execute as formulas when the export is opened in Excel.
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// maxBanDurationSecs caps ban TTLs at one year — beyond that, use a permanent ban.
const maxBanDurationSecs = 365 * 24 * 3600

func valOrZero(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func parseIntQuery(r *http.Request, key string, def int) int {
	if raw := r.URL.Query().Get(key); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return def
}

// rateLimiter is a simple token-bucket rate limiter. Tokens are tracked as
// float64: with integer math, requests arriving faster than one per
// 1/rate second would each round the refill down to zero while still
// advancing `last`, so the bucket would never refill under sustained load.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64 // tokens added per second
	last   time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{tokens: float64(burst), max: float64(burst), rate: float64(rate), last: time.Now()}
}

func (rl *rateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.max {
		rl.tokens = rl.max
	}
	if rl.tokens < 1 {
		return false
	}
	rl.tokens--
	return true
}

// normalizeIP converts IPv4-mapped IPv6 addresses ("::ffff:1.2.3.4") to their
// plain IPv4 form ("1.2.3.4") so string comparisons are reliable across
// dual-stack connections.
func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// clientIP returns the normalized IP the request originated from. When the
// direct peer is a loopback/private address (i.e. a reverse proxy on the same
// host or LAN), the last X-Forwarded-For hop — the one appended by that
// trusted proxy — is used instead. XFF from public peers is ignored because
// it is trivially spoofable.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = normalizeIP(host)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && responder.IsPrivate(host) {
		parts := strings.Split(xff, ",")
		candidate := normalizeIP(strings.TrimSpace(parts[len(parts)-1]))
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return host
}
