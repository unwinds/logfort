package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/unwinds/logfort/internal/api"
	"github.com/unwinds/logfort/internal/config"
	"github.com/unwinds/logfort/internal/f2b"
	"github.com/unwinds/logfort/internal/geo"
	"github.com/unwinds/logfort/internal/hostinfo"
	"github.com/unwinds/logfort/internal/ingest"
	"github.com/unwinds/logfort/internal/netwatch"
	"github.com/unwinds/logfort/internal/notify"
	"github.com/unwinds/logfort/internal/parse"
	"github.com/unwinds/logfort/internal/responder"
	"github.com/unwinds/logfort/internal/store"
	"github.com/unwinds/logfort/internal/threat"
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
	if cfg.DemoMode {
		slog.Warn("DEMO MODE: real logs are not read, all events are synthetic (unset LOGFORT_DEMO for production)")
		sources = []ingest.Source{ingest.NewDemoSource()}
	} else if cfg.Backend == "file" {
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
	// Optional ASN database (DB-IP ASN Lite / GeoLite2-ASN) — enriches events
	// with the attacker's network operator, still without any outbound lookups.
	asnLoaded := false
	if cfg.ASNDB != "" {
		asnDB, err := geo.OpenASN(cfg.ASNDB)
		if err != nil {
			slog.Warn("ASN database unavailable, asn fields will be empty",
				"path", cfg.ASNDB, "err", err)
		} else {
			defer asnDB.Close()
			looker = geo.WithASN{City: looker, ASN: asnDB}
			asnLoaded = true
			slog.Info("ASN database loaded", "path", cfg.ASNDB)
		}
	}

	// Optional threat-intel blocklist (local file of IPs/CIDRs). A match flags
	// the event (red badge, `threat` column) and, when LOGFORT_BLOCKLIST_AUTOBAN
	// is set, triggers an immediate ban. All lookups stay local.
	var blocklist *threat.List
	if cfg.Blocklist != "" {
		bl, err := threat.Open(cfg.Blocklist)
		if err != nil {
			slog.Warn("blocklist unavailable, threat enrichment disabled",
				"path", cfg.Blocklist, "err", err)
		} else {
			blocklist = bl
			slog.Info("threat blocklist loaded",
				"path", cfg.Blocklist, "entries", bl.Count(), "autoban", cfg.BlocklistAutoBan)
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
	pipeline.SetBlocklist(blocklist)

	srv := api.New(cfg, st, version)
	srv.SetEnvNotifyConfig(envCfg)
	srv.SetGeoIPEnabled(geoIPLoaded)
	srv.SetASNEnabled(asnLoaded)
	srv.SetBlocklist(blocklist, cfg.BlocklistAutoBan)
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
		srv.NotifyEvent(ev)    // uses current dispatcher, swappable via settings API
		srv.AutoBanEvent(ev)   // auto-ban if threshold exceeded and feature is enabled
		srv.ThreatBanEvent(ev) // immediate ban if the IP is on the threat blocklist
	})

	// Host vitals sampler (CPU/mem/disk/load from local /proc; no-op off Linux).
	vitals := hostinfo.NewSampler(filepath.Dir(cfg.DBPath))
	if vitals.Available() {
		srv.SetVitalsFunc(vitals.Snapshot)
		slog.Info("host vitals sampling enabled")
	}

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

	// Lift bans whose TTL has passed. Runs even with the responder disabled:
	// rows with an expiry may remain from when it was enabled, and they must
	// still flip to inactive (Unban on NoopResponder is a no-op).
	go runBanExpiry(ctx, st, resp, srv)

	// Host-vitals alerting (disk almost full) — edge-triggered so it fires once
	// per breach, not every tick.
	if vitals.Available() {
		go vitals.Start(ctx)
		go runVitalsAlerts(ctx, vitals, srv)
	}

	// TLS certificate expiry monitoring for the configured endpoints.
	if len(cfg.TLSWatch) > 0 {
		go runCertWatch(ctx, cfg.TLSWatch, srv)
		slog.Info("TLS certificate monitoring enabled", "targets", cfg.TLSWatch)
	}

	// Listening-port monitoring: alert when a new TCP port starts listening
	// (possible backdoor). Opt-in; only meaningful with host network visibility.
	if cfg.PortsWatch {
		if netwatch.PortsAvailable {
			go runPortsWatch(ctx, srv)
			slog.Info("listening-port monitoring enabled")
		} else {
			slog.Warn("LOGFORT_PORTS_WATCH is set but port enumeration is unavailable on this platform")
		}
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
	now := time.Now().Unix()
	for _, b := range bans {
		if b.Source != resp.Name() {
			continue
		}
		// Skip bans that expired while the process was down — the expiry
		// sweeper will mark them inactive; re-adding them first would leave
		// a firewall entry the sweeper immediately has to remove again.
		if b.ExpiresAt != nil && *b.ExpiresAt <= now {
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

// runBanExpiry lifts bans whose TTL has passed: firewall unban first (kept
// active and retried on the next sweep if that fails), then the DB row flips
// to inactive and an "unban" event lands in the feed.
func runBanExpiry(ctx context.Context, st store.Store, resp responder.Responder, srv *api.Server) {
	sweep := func() {
		expired, err := st.ListExpiredBans(ctx, time.Now())
		if err != nil {
			slog.Error("ban expiry: list", "err", err)
			return
		}
		for _, b := range expired {
			if ctx.Err() != nil {
				return
			}
			if err := resp.Unban(ctx, b.IP); err != nil {
				slog.Warn("ban expiry: firewall unban failed, will retry", "ip", b.IP, "err", err)
				continue
			}
			if err := st.UnbanIP(ctx, b.IP); err != nil {
				slog.Error("ban expiry: store unban", "ip", b.IP, "err", err)
				continue
			}
			slog.Info("ban expired", "ip", b.IP, "source", b.Source)
			ev := &parse.Event{TS: time.Now().UTC(), IP: b.IP, EventType: "unban", Source: "expiry"}
			if err := st.InsertEvent(ctx, ev); err != nil && !errors.Is(err, store.ErrDuplicate) {
				slog.Warn("ban expiry: record unban event", "ip", b.IP, "err", err)
			}
			srv.PublishEvent(ev)
		}
	}

	sweep()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// runVitalsAlerts pushes a single alert when the data volume crosses the
// critical fill threshold, re-arming once usage drops back with hysteresis.
func runVitalsAlerts(ctx context.Context, v *hostinfo.Sampler, srv *api.Server) {
	const critPercent = 90.0
	alerted := false
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := v.Snapshot()
			if !snap.Available || snap.DiskTotal == 0 {
				continue
			}
			switch {
			case snap.DiskUsedPercent >= critPercent && !alerted:
				alerted = true
				srv.SendAlert("LogFort: disk almost full",
					fmt.Sprintf("%s is %.1f%% full (%.1f GB free).",
						snap.DiskPath, snap.DiskUsedPercent, float64(snap.DiskFree)/1e9))
			case snap.DiskUsedPercent < critPercent-5:
				alerted = false
			}
		}
	}
}

// runCertWatch probes the configured TLS endpoints for certificate expiry,
// alerting once per endpoint when the remaining lifetime drops to the warning
// window. Results feed /api/vitals.
func runCertWatch(ctx context.Context, targets []string, srv *api.Server) {
	const warnDays = 14
	warned := make(map[string]bool)
	check := func() {
		results := make([]netwatch.CertStatus, 0, len(targets))
		for _, t := range targets {
			if ctx.Err() != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			cs := netwatch.CheckCert(cctx, t)
			cancel()
			results = append(results, cs)
			if cs.Error != "" {
				continue
			}
			if cs.DaysLeft <= warnDays {
				if !warned[t] {
					warned[t] = true
					srv.SendAlert("LogFort: TLS certificate expiring",
						fmt.Sprintf("%s expires in %d day(s).", cs.Target, cs.DaysLeft))
				}
			} else {
				warned[t] = false
			}
		}
		srv.SetCertStatus(results)
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}
	check()
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// runPortsWatch snapshots locally-listening TCP ports every minute and alerts
// when a new one appears (a common backdoor signature). The first scan sets the
// baseline silently.
func runPortsWatch(ctx context.Context, srv *api.Server) {
	var baseline map[int]bool
	scan := func() {
		ports, err := netwatch.ListeningPorts()
		if err != nil {
			slog.Warn("listening-port scan failed", "err", err)
			return
		}
		srv.SetListeningPorts(ports)
		cur := make(map[int]bool, len(ports))
		for _, p := range ports {
			cur[p] = true
		}
		if baseline == nil {
			baseline = cur
			return
		}
		var added []int
		for p := range cur {
			if !baseline[p] {
				added = append(added, p)
			}
		}
		if len(added) > 0 {
			sort.Ints(added)
			srv.SendAlert("LogFort: new listening port",
				fmt.Sprintf("New TCP port(s) now listening: %v", added))
			baseline = cur
		}
	}

	scan()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
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
