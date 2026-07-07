package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/unwinds/logfort/internal/api"
	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/f2b"
	"github.com/unwinds/logfort/internal/geo"
	"github.com/unwinds/logfort/internal/ingest"
	"github.com/unwinds/logfort/internal/notify"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/responder"
	"github.com/unwinds/logfort/internal/store"
)

// version is set at build time via -X main.version=<tag>.
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version", "-v":
			fmt.Println("logfort " + version)
			return
		}
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "err", err)
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	})))

	st, err := store.New(cfg.DBPath)
	if err != nil {
		slog.Error("cannot open database", "path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// Save env-var-only notify values before DB overlay so the API server can
	// enforce "env vars always win" even when settings are updated at runtime.
	envCfg := *cfg

	// Overlay notification settings saved via the UI (env vars take priority).
	if dbSettings, err := st.GetAllSettings(context.Background()); err == nil {
		cfg.OverlaySettings(dbSettings)
	}

	// Build log sources.
	var sources []ingest.Source
	if cfg.Backend == "file" {
		if len(cfg.LogPaths) == 0 {
			slog.Error("no log paths configured; set LOGFORT_LOG_PATHS")
			os.Exit(1)
		}
		for _, p := range cfg.LogPaths {
			sources = append(sources, ingest.NewFileSource(p))
		}
		if cfg.Fail2BanLog != "" {
			sources = append(sources, ingest.NewFileSourceFromStart(cfg.Fail2BanLog))
		}
	} else if cfg.Backend == "journald" {
		sources = append(sources, ingest.NewJournaldSource(cfg.JournaldUnit))
		if cfg.Fail2BanLog != "" {
			sources = append(sources, ingest.NewFileSourceFromStart(cfg.Fail2BanLog))
		}
	} else {
		slog.Error("unsupported backend", "backend", cfg.Backend)
		os.Exit(1)
	}

	// Open GeoIP database (optional — graceful fallback to noop).
	var looker geo.Looker = geo.NoopLooker{}
	geoIPLoaded := false
	if cfg.GeoIPDB != "" {
		geoDB, err := geo.Open(cfg.GeoIPDB)
		if err != nil {
			slog.Warn("GeoIP database unavailable, geo fields will be empty",
				"path", cfg.GeoIPDB, "err", err)
		} else {
			defer geoDB.Close()
			looker = geoDB
			geoIPLoaded = true
			slog.Info("GeoIP database loaded", "path", cfg.GeoIPDB)
		}
	}

	// Build responder (noop if LOGFORT_RESPONDER_ENABLED=false).
	resp, allowlist, err := responder.New(cfg)
	if err != nil {
		slog.Error("responder init failed", "err", err)
		os.Exit(1)
	}
	if cfg.ResponderEnabled {
		slog.Info("responder enabled", "backend", resp.Name())
	}
	// Extra allowlist entries added from the settings UI (persisted in DB).
	// Bad stored data must not kill startup — warn and continue with the base list.
	if len(cfg.ExtraIgnoreIPs) > 0 {
		if err := allowlist.SetExtra(cfg.ExtraIgnoreIPs); err != nil {
			slog.Warn("ignoring invalid extra allowlist entries from settings", "err", err)
		}
	}

	// Build notify dispatcher (nil if no notifiers or rules configured).
	dispatcher, err := notify.New(cfg, st)
	if err != nil {
		slog.Error("notify init failed", "err", err)
		os.Exit(1)
	}
	if dispatcher != nil {
		slog.Info("notify enabled", "rules", cfg.NotifyRules)
	}

	pipeline := ingest.NewPipeline(sources, parse.ParseLine, st)
	pipeline.SetGeo(looker)

	srv := api.New(cfg, st, version)
	srv.SetEnvNotifyConfig(envCfg)
	srv.SetGeoIPEnabled(geoIPLoaded)
	srv.SetResponder(resp, allowlist)
	srv.SetCounterFunc(pipeline.Counters)
	srv.SetSourceStatusFunc(pipeline.SourceStatuses)
	srv.SetDispatcher(dispatcher) // nil-safe; wires Dispatcher.Notify and enables Stop() on swap

	// fail2ban jail manager: powers the Firewall settings tab (maxretry /
	// bantime editable from the UI) whenever the fail2ban socket is mounted
	// or fail2ban-client is available.
	f2bMgr := f2b.NewManager(cfg.Fail2BanSocket, cfg.Fail2BanJail)
	if f2bMgr.Available() {
		srv.SetF2BManager(f2bMgr)
		slog.Info("fail2ban integration available", "socket", cfg.Fail2BanSocket, "jail", cfg.Fail2BanJail)
	}
	pipeline.SetPublishHook(func(ev *parse.Event) {
		srv.PublishEvent(ev)
		srv.NotifyEvent(ev)  // uses current dispatcher, swappable via settings API
		srv.AutoBanEvent(ev) // auto-ban if threshold exceeded and feature is enabled
	})

	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      srv,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start HTTP server.
	go func() {
		slog.Info("logfort started", "addr", cfg.Listen, "version", version)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server error", "err", err)
			stop()
		}
	}()

	// Start ingest pipeline.
	go func() {
		if err := pipeline.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("pipeline error", "err", err)
		}
	}()

	// Start retention cleanup goroutine — reads current retention_days from DB on each tick
	// so that changes made via the settings UI take effect without a restart.
	go runRetention(ctx, st, cfg.RetentionDays)

	// Re-apply UI-managed fail2ban jail settings. `set <jail> …` socket
	// commands are runtime-only and vanish when fail2ban restarts, so the
	// stored values are enforced at startup and refreshed periodically.
	if f2bMgr.Available() {
		go runF2BEnforce(ctx, st, f2bMgr)
	}

	// Re-apply active bans to the firewall. nftables sets live in kernel
	// memory and are empty after a host reboot, while the DB still lists the
	// bans as active. fail2ban restores its own bans, so only nftables needs this.
	if cfg.ResponderEnabled && resp.Name() == "nftables" {
		go reconcileBans(ctx, st, resp)
	}

	// Wait for shutdown signal.
	<-ctx.Done()
	slog.Info("shutting down")

	// Disconnect SSE streams first — otherwise http.Server.Shutdown waits its
	// full timeout for connections that would never finish on their own.
	srv.Shutdown()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		slog.Error("http shutdown", "err", err)
	}
	srv.Close()
}

// reconcileBans re-applies active bans recorded by this responder backend to
// the firewall. Bans mirrored from fail2ban.log (source="fail2ban") are
// skipped — fail2ban manages its own persistence.
func reconcileBans(ctx context.Context, st store.Store, resp responder.Responder) {
	bans, err := st.ListBans(ctx, true)
	if err != nil {
		slog.Warn("ban reconciliation: list bans", "err", err)
		return
	}
	applied := 0
	for _, b := range bans {
		if b.Source != resp.Name() {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if err := resp.Ban(ctx, b.IP); err != nil {
			slog.Warn("ban reconciliation failed", "ip", b.IP, "err", err)
			continue
		}
		applied++
	}
	if applied > 0 {
		slog.Info("re-applied active bans to firewall", "count", applied)
	}
}

// runF2BEnforce keeps the running fail2ban jail in sync with the UI-managed
// settings stored in the DB. Reads fresh values on every tick so UI changes
// are picked up, and re-applies them every 10 minutes because a fail2ban
// restart silently reverts runtime `set` commands to the jail.d file values.
func runF2BEnforce(ctx context.Context, st store.Store, mgr *f2b.Manager) {
	apply := func() {
		desired := f2b.JailSettings{}
		if v, ok, err := st.GetSetting(ctx, "f2b.maxretry"); err == nil && ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				desired.MaxRetry = n
			}
		}
		if v, ok, err := st.GetSetting(ctx, "f2b.bantime"); err == nil && ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				desired.BanTimeSecs = n
			}
		}
		if v, ok, err := st.GetSetting(ctx, "f2b.findtime"); err == nil && ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				desired.FindTimeSecs = n
			}
		}
		if desired == (f2b.JailSettings{}) {
			return // never configured from the UI — leave fail2ban alone
		}
		applyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if live, err := mgr.GetJail(applyCtx); err == nil {
			match := (desired.MaxRetry == 0 || live.MaxRetry == desired.MaxRetry) &&
				(desired.BanTimeSecs == 0 || live.BanTimeSecs == desired.BanTimeSecs) &&
				(desired.FindTimeSecs == 0 || live.FindTimeSecs == desired.FindTimeSecs)
			if match {
				return
			}
		}
		if err := mgr.SetJail(applyCtx, desired); err != nil {
			slog.Warn("fail2ban settings enforcement failed", "err", err)
			return
		}
		slog.Info("re-applied fail2ban jail settings",
			"jail", mgr.Jail(), "maxretry", desired.MaxRetry,
			"bantime_s", desired.BanTimeSecs, "findtime_s", desired.FindTimeSecs)
	}

	// Initial apply with a few quick retries: at container start fail2ban may
	// still be booting on the host.
	for _, delay := range []time.Duration{0, 15 * time.Second, 45 * time.Second} {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		apply()
	}

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			apply()
		}
	}
}

func runRetention(ctx context.Context, st store.Store, defaultDays int) {
	cleanup := func() {
		days := defaultDays
		// Read the current retention_days from DB in case it was changed via the UI.
		if v, ok, err := st.GetSetting(ctx, "general.retention_days"); err == nil && ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				days = n
			}
		}
		n, err := st.DeleteOldEvents(ctx, days)
		if err != nil {
			slog.Error("retention cleanup", "err", err)
		} else if n > 0 {
			slog.Info("retention cleanup", "deleted", n, "retention_days", days)
		}
	}

	// Run once at startup — a ticker alone never fires on hosts that restart
	// the container more often than every 24 h.
	cleanup()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}
