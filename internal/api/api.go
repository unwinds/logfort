package api

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	webui "github.com/unwinds/sshwatch/web"
	"github.com/unwinds/sshwatch/internal/config"
	"github.com/unwinds/sshwatch/internal/parse"
	"github.com/unwinds/sshwatch/internal/store"
)

// Server holds API dependencies and implements http.Handler.
type Server struct {
	cfg     *config.Config
	store   store.Store
	mux     *http.ServeMux
	hub     *Hub
	version string
	startTS time.Time

	parsedFn func() (int64, int64)
}

// New creates and configures the HTTP server.
func New(cfg *config.Config, st store.Store, version string) *Server {
	s := &Server{
		cfg:     cfg,
		store:   st,
		version: version,
		startTS: time.Now(),
		mux:     http.NewServeMux(),
		hub:     newHub(),
	}
	s.routes()
	return s
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

// Close shuts down the SSE hub. Call after the HTTP server has stopped.
func (s *Server) Close() { s.hub.close() }

// SetCounterFunc wires the pipeline's parsed/unparsed counters into /api/health.
func (s *Server) SetCounterFunc(fn func() (int64, int64)) {
	s.parsedFn = fn
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// API endpoints.
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/events", s.handleEvents)
	s.mux.HandleFunc("GET /api/bans", s.handleBans)
	s.mux.HandleFunc("GET /api/map", s.handleMap)
	s.mux.HandleFunc("GET /api/stream", s.handleStream)

	// Write endpoints (require responder enabled).
	s.mux.HandleFunc("POST /api/ban", s.handleBanPost)
	s.mux.HandleFunc("POST /api/unban", s.handleUnbanPost)

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

	resp := map[string]any{
		"status":         "ok",
		"version":        s.version,
		"uptime_s":       int64(time.Since(s.startTS).Seconds()),
		"parsed_total":   parsed,
		"unparsed_total": unparsed,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}
	st, err := s.store.GetStats(r.Context(), window)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := store.EventQuery{
		Limit:     parseIntQuery(r, "limit", 100),
		Offset:    parseIntQuery(r, "offset", 0),
		EventType: r.URL.Query().Get("type"),
		IP:        r.URL.Query().Get("ip"),
		Country:   r.URL.Query().Get("country"),
	}
	if q.Limit > 1000 {
		q.Limit = 1000
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
	points, err := s.store.GetMapPoints(r.Context(), window)
	if err != nil {
		slog.Error("map points", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if points == nil {
		points = []store.MapPoint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": points})
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

func (s *Server) handleBanPost(w http.ResponseWriter, _ *http.Request) {
	if !s.cfg.ResponderEnabled {
		writeError(w, http.StatusForbidden, "responder is disabled; set SSHWATCH_RESPONDER_ENABLED=true to enable")
		return
	}
	writeError(w, http.StatusNotImplemented, "responder backend not implemented yet (v0.6)")
}

func (s *Server) handleUnbanPost(w http.ResponseWriter, _ *http.Request) {
	if !s.cfg.ResponderEnabled {
		writeError(w, http.StatusForbidden, "responder is disabled; set SSHWATCH_RESPONDER_ENABLED=true to enable")
		return
	}
	writeError(w, http.StatusNotImplemented, "responder backend not implemented yet (v0.6)")
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

func parseIntQuery(r *http.Request, key string, def int) int {
	if raw := r.URL.Query().Get(key); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return def
}
