package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	webui "github.com/unwinds/logfort/web"
	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/notify"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/responder"
	"github.com/unwinds/logfort/internal/store"
)

// Server holds API dependencies and implements http.Handler.
type Server struct {
	cfg       *config.Config
	envCfg    config.Config // notify fields as loaded from env vars (pre-DB-overlay); gates UI writes
	cfgMu     sync.RWMutex // protects runtime-mutable notify/autoban/retention fields of cfg
	store     store.Store
	mux       *http.ServeMux
	handler   http.Handler // pre-built: mux wrapped with basicAuth when auth is enabled
	hub       *Hub
	version   string
	startTS   time.Time
	parsedFn  func() (int64, int64)
	responder responder.Responder
	allowlist *responder.Allowlist
	banLim    *rateLimiter // limits ban requests only; unban is not throttled
	notifyMu  sync.RWMutex
	notifyFn  func(*parse.Event)
	notifyDisp *notify.Dispatcher // tracked for Stop() on replacement
	geoIPEnabled    bool
	autoBanCooldown sync.Map    // IP string → time.Time; prevents duplicate bans within window
	autoBanSem      chan struct{} // limits concurrent auto-ban background goroutines
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
	return s
}

// SetResponder wires an active responder and its allowlist into the server.
func (s *Server) SetResponder(r responder.Responder, al *responder.Allowlist) {
	s.responder = r
	s.allowlist = al
}

// SetGeoIPEnabled records whether a GeoIP database was successfully loaded.
func (s *Server) SetGeoIPEnabled(v bool) { s.geoIPEnabled = v }

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
	s.mux.HandleFunc("GET /api/bans", s.handleBans)
	s.mux.HandleFunc("GET /api/map", s.handleMap)
	s.mux.HandleFunc("GET /api/stream", s.handleStream)

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
	resp := map[string]any{
		"status":            "ok",
		"version":           s.version,
		"uptime_s":          int64(time.Since(s.startTS).Seconds()),
		"parsed_total":      parsed,
		"unparsed_total":    unparsed,
		"responder_enabled": s.cfg.ResponderEnabled,
		"responder_backend": s.responder.Name(),
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
	resp := map[string]any{"points": points}
	if s.cfg.HomeLat != nil && s.cfg.HomeLon != nil {
		resp["home_lat"] = *s.cfg.HomeLat
		resp["home_lon"] = *s.cfg.HomeLon
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
		IP     string `json:"ip"`
		Reason string `json:"reason"`
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
	// Anti-self-lockout: normalize both IPs to handle IPv4-mapped IPv6
	// (r.RemoteAddr may be "[::ffff:1.2.3.4]:PORT" when req.IP is "1.2.3.4").
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if normalizeIP(remoteIP) == normalizeIP(req.IP) {
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

	// Record in store first; roll back if the firewall operation fails.
	if err := s.store.BanIP(r.Context(), req.IP, s.responder.Name(), req.Reason); err != nil {
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
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	slog.Info("manual unban", "ip", req.IP, "remote", remoteIP, "backend", s.responder.Name())
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": req.IP})
}

// --- settings handlers ---

func (s *Server) handleGetSystem(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"backend":           s.cfg.Backend,
		"log_paths":         s.cfg.LogPaths,
		"fail2ban_log":      s.cfg.Fail2BanLog,
		"journald_unit":     s.cfg.JournaldUnit,
		"geoip_enabled":     s.geoIPEnabled,
		"responder_enabled": s.cfg.ResponderEnabled,
		"responder_backend": s.responder.Name(),
		"fail2ban_jail":     s.cfg.Fail2BanJail,
		"auth_enabled":      s.cfg.AuthEnabled,
		"listen":            s.cfg.Listen,
	})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	resp := map[string]any{
		"telegram_token":    s.cfg.NotifyTelegramToken,
		"telegram_chat_id":  s.cfg.NotifyTelegramChat,
		"discord_url":       s.cfg.NotifyDiscordURL,
		"webhook_url":       s.cfg.NotifyWebhookURL,
		"rules":             strings.Join(s.cfg.NotifyRules, ","),
		"retention_days":    s.cfg.RetentionDays,
		"autoban_enabled":   s.cfg.AutoBanEnabled,
		"autoban_threshold": s.cfg.AutoBanThreshold,
		"autoban_window":    s.cfg.AutoBanWindow,
	}
	s.cfgMu.RUnlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePostSettings(w http.ResponseWriter, r *http.Request) {
	// Pointer fields: nil means "field not present in request → don't change".
	var req struct {
		TelegramToken *string `json:"telegram_token"`
		TelegramChat  *string `json:"telegram_chat_id"`
		DiscordURL    *string `json:"discord_url"`
		WebhookURL    *string `json:"webhook_url"`
		Rules         *string `json:"rules"`
		// General settings
		RetentionDays    *int    `json:"retention_days"`
		AutoBanEnabled   *bool   `json:"autoban_enabled"`
		AutoBanThreshold *int    `json:"autoban_threshold"`
		AutoBanWindow    *string `json:"autoban_window"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Build the effective config: start from current, apply request values only
	// for fields not pinned by env vars.
	s.cfgMu.RLock()
	proposed := *s.cfg
	s.cfgMu.RUnlock()

	// Notify fields (env vars pin their values; nil request field = skip).
	if req.TelegramToken != nil && s.envCfg.NotifyTelegramToken == "" {
		proposed.NotifyTelegramToken = *req.TelegramToken
	}
	if req.TelegramChat != nil && s.envCfg.NotifyTelegramChat == "" {
		proposed.NotifyTelegramChat = *req.TelegramChat
	}
	if req.DiscordURL != nil && s.envCfg.NotifyDiscordURL == "" {
		proposed.NotifyDiscordURL = *req.DiscordURL
	}
	if req.WebhookURL != nil && s.envCfg.NotifyWebhookURL == "" {
		proposed.NotifyWebhookURL = *req.WebhookURL
	}
	if req.Rules != nil && len(s.envCfg.NotifyRules) == 0 {
		proposed.NotifyRules = nil
		for _, rule := range strings.Split(*req.Rules, ",") {
			if rule = strings.TrimSpace(rule); rule != "" {
				proposed.NotifyRules = append(proposed.NotifyRules, rule)
			}
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

	// Validate notify config before touching the DB.
	d, err := notify.New(&proposed, s.store)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid settings: "+err.Error())
		return
	}

	// Collect all changed fields and persist atomically in a single transaction.
	toSave := make(map[string]string)
	if req.TelegramToken != nil {
		toSave["notify.telegram.token"] = *req.TelegramToken
	}
	if req.TelegramChat != nil {
		toSave["notify.telegram.chat_id"] = *req.TelegramChat
	}
	if req.DiscordURL != nil {
		toSave["notify.discord.url"] = *req.DiscordURL
	}
	if req.WebhookURL != nil {
		toSave["notify.webhook.url"] = *req.WebhookURL
	}
	if req.Rules != nil {
		toSave["notify.rules"] = *req.Rules
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
	if len(toSave) > 0 {
		if err := s.store.SetSettings(r.Context(), toSave); err != nil {
			slog.Error("save settings", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to save settings")
			return
		}
	}

	// Apply effective config to in-memory state.
	s.cfgMu.Lock()
	s.cfg.NotifyTelegramToken = proposed.NotifyTelegramToken
	s.cfg.NotifyTelegramChat = proposed.NotifyTelegramChat
	s.cfg.NotifyDiscordURL = proposed.NotifyDiscordURL
	s.cfg.NotifyWebhookURL = proposed.NotifyWebhookURL
	s.cfg.NotifyRules = proposed.NotifyRules
	s.cfg.RetentionDays = proposed.RetentionDays
	s.cfg.AutoBanEnabled = proposed.AutoBanEnabled
	s.cfg.AutoBanThreshold = proposed.AutoBanThreshold
	s.cfg.AutoBanWindow = proposed.AutoBanWindow
	s.cfgMu.Unlock()

	// Swap dispatcher only if notify fields were included in this request.
	if req.TelegramToken != nil || req.TelegramChat != nil ||
		req.DiscordURL != nil || req.WebhookURL != nil || req.Rules != nil {
		s.swapDispatcher(d)
	} else {
		d.Stop() // nil-safe; discard the unused validation dispatcher
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	s.notifyMu.RLock()
	hasNotifier := s.notifyFn != nil
	s.notifyMu.RUnlock()
	if !hasNotifier {
		writeError(w, http.StatusBadRequest, "no notifiers configured — save settings first")
		return
	}
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
	s.cfgMu.RUnlock()

	if !enabled || !responderEnabled {
		return
	}
	// Only react to auth-failure events, not to bans/unbans/accepted logins.
	switch ev.EventType {
	case "ban", "unban", "accepted":
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
		s.autoBanBackground(ip, threshold, dur, now)
	}()
}

func (s *Server) autoBanBackground(ip string, threshold int, dur time.Duration, now time.Time) {
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

	if err := s.store.BanIP(ctx, ip, s.responder.Name(), "auto-ban"); err != nil {
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

func parseIntQuery(r *http.Request, key string, def int) int {
	if raw := r.URL.Query().Get(key); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return def
}

// rateLimiter is a simple token-bucket rate limiter.
type rateLimiter struct {
	mu     sync.Mutex
	tokens int
	max    int
	rate   int // tokens added per second
	last   time.Time
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{tokens: burst, max: burst, rate: rate, last: time.Now()}
}

func (rl *rateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now
	rl.tokens += int(elapsed * float64(rl.rate))
	if rl.tokens > rl.max {
		rl.tokens = rl.max
	}
	if rl.tokens <= 0 {
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
