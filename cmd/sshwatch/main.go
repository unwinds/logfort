package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/unwinds/sshwatch/internal/api"
	"github.com/unwinds/sshwatch/internal/config"
	"github.com/unwinds/sshwatch/internal/geo"
	"github.com/unwinds/sshwatch/internal/ingest"
	"github.com/unwinds/sshwatch/internal/parse"
	"github.com/unwinds/sshwatch/internal/store"
)

const version = "0.3.0"

func main() {
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

	// Build log sources.
	var sources []ingest.Source
	if cfg.Backend == "file" {
		if len(cfg.LogPaths) == 0 {
			slog.Error("no log paths configured; set SSHWATCH_LOG_PATHS")
			os.Exit(1)
		}
		for _, p := range cfg.LogPaths {
			sources = append(sources, ingest.NewFileSource(p))
		}
		if cfg.Fail2BanLog != "" {
			sources = append(sources, ingest.NewFileSource(cfg.Fail2BanLog))
		}
	} else {
		slog.Error("unsupported backend (journald support coming in a future release)", "backend", cfg.Backend)
		os.Exit(1)
	}

	// Open GeoIP database (optional — graceful fallback to noop).
	var looker geo.Looker = geo.NoopLooker{}
	if cfg.GeoIPDB != "" {
		geoDB, err := geo.Open(cfg.GeoIPDB)
		if err != nil {
			slog.Warn("GeoIP database unavailable, geo fields will be empty",
				"path", cfg.GeoIPDB, "err", err)
		} else {
			defer geoDB.Close()
			looker = geoDB
			slog.Info("GeoIP database loaded", "path", cfg.GeoIPDB)
		}
	}

	pipeline := ingest.NewPipeline(sources, parse.ParseLine, st)
	pipeline.SetGeo(looker)

	srv := api.New(cfg, st, version)
	srv.SetCounterFunc(pipeline.Counters)
	pipeline.SetPublishHook(srv.PublishEvent)

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
		slog.Info("sshwatch started", "addr", cfg.Listen, "version", version)
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

	// Start retention cleanup goroutine.
	go runRetention(ctx, st, cfg.RetentionDays)

	// Wait for shutdown signal.
	<-ctx.Done()
	slog.Info("shutting down")

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		slog.Error("http shutdown", "err", err)
	}
	srv.Close()
}

func runRetention(ctx context.Context, st store.Store, days int) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := st.DeleteOldEvents(ctx, days)
			if err != nil {
				slog.Error("retention cleanup", "err", err)
			} else if n > 0 {
				slog.Info("retention cleanup", "deleted", n, "retention_days", days)
			}
		}
	}
}
