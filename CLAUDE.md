# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -ldflags="-X main.version=dev" -o ./logfort ./cmd/logfort

# Lint
golangci-lint run

# Tests (always run with -race)
go test -race ./...
go test -race ./internal/parse/...          # one package
go test -race -run TestGetStats ./internal/store/...  # one test

# Run locally on the test fixture (no real log required)
LOGFORT_LOG_PATHS=$(pwd)/testdata/auth_debian.log \
LOGFORT_DB_PATH=/tmp/logfort-dev.db \
LOGFORT_LISTEN=127.0.0.1:8080 \
go run ./cmd/logfort

# With fail2ban bans (LOGFORT_FAIL2BAN_LOG is optional; parsed as a second file source)
LOGFORT_LOG_PATHS=$(pwd)/testdata/auth_debian.log \
LOGFORT_FAIL2BAN_LOG=/var/log/fail2ban.log \
LOGFORT_DB_PATH=/tmp/logfort-dev.db \
LOGFORT_LISTEN=127.0.0.1:8080 \
go run ./cmd/logfort

# Run with GeoIP — use testdata/auth_public.log (real public IPs) for attack map testing
# Download DB-IP Lite: curl -L "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz" | gunzip > /tmp/dbip-city.mmdb
LOGFORT_LOG_PATHS=$(pwd)/testdata/auth_public.log \
LOGFORT_DB_PATH=/tmp/logfort-dev.db \
LOGFORT_GEOIP_DB=/tmp/dbip-city.mmdb \
LOGFORT_LISTEN=127.0.0.1:8080 \
go run ./cmd/logfort

# Simulate live traffic (second terminal while server is running)
while true; do
  NOW=$(date '+%b %e %H:%M:%S')
  IP="$((RANDOM%200+10)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))"
  USERS=(root admin ubuntu deploy git test oracle)
  USER=${USERS[$RANDOM % ${#USERS[@]}]}
  echo "$NOW myhost sshd[$$]: Failed password for invalid user $USER from $IP port $((RANDOM%30000+30000)) ssh2" >> /tmp/fake.log
  sleep 0.5
done

# Docker
docker build -t logfort:dev .
docker run --rm -p 127.0.0.1:8080:8080 \
  -v /var/log/auth.log:/host/auth.log:ro \
  -v /tmp/logfort-data:/data \
  logfort:dev
```

## Architecture

Data flows in one direction: **ingest → parse → geo → store → API/notify**.

```
fileSource (nxadm/tail, ReOpen=true handles rotation)
journaldSource (subprocess journalctl -o json --follow --lines=0 --unit=<unit>)
    │  chan string (buf 1000)
    ▼
Pipeline workers (×4)
    │  parse.ParseLine()      → ErrNoMatch = silently skip
    │  geo.Looker.Lookup(ip)  → fills Event.Geo (noop if no mmdb)
    │  store.InsertEvent()    → ErrDuplicate = skip publish (log re-read on restart)
    └─ publish hook → SSE hub + notify.Dispatcher (both wired in main)

api.Server  (stdlib ServeMux, Go ≥1.22 method+path patterns)
    ├─ GET /api/health|stats|events|bans|map|stream
    │     └─ /api/health includes `sources` ([]ingest.SourceStatus) + `sources_ok`; the UI renders a
    │        red banner (#src-banner) when any source has state="error" (unreadable/missing log file).
    │        Also runs store.Ping as an end-to-end DB probe → `db_ok`; on failure returns HTTP 503 with
    │        status="degraded" so the Docker HEALTHCHECK flips when SQLite dies
    ├─ GET /api/events.csv         → CSV export, same filter params as /api/events (limit cap 10000);
    │                                 csvCell() prefixes =+-@ cells with ' (spreadsheet formula injection)
    ├─ GET /api/bans.csv           → ban-history CSV export (same `active` param as /api/bans)
    ├─ GET /api/backup             → point-in-time SQLite snapshot download: store.Backup (VACUUM INTO) to a
    │                                 temp file, streamed with Content-Length, deleted afterwards
    ├─ GET /metrics                → Prometheus text format, hand-rolled (no client lib); NOT auth-exempt;
    │                                 gauges include logfort_sse_clients (Hub.clientCount, atomic) and
    │                                 logfort_db_size_bytes (os.Stat on plain DB paths only)
    ├─ GET /api/system             → read-only runtime config (backend, paths, geoip, responder, auth)
    │                                 + f2b_available (fail2ban socket or fail2ban-client reachable)
    │                                 + db_path / db_size_bytes
    ├─ POST /api/ban|unban  (403 when responder disabled)
    │     └─ on success: InsertEvent (ban/unban appears in the events feed) + PublishEvent + NotifyEvent
    ├─ GET  /api/settings          → all UI-configurable settings (notify + retention + autoban + allowlist)
    │                                 + `env_locked` (fields pinned by env vars → UI disables inputs)
    │                                 + `ignore_ips` (UI-added allowlist) / `ignore_ips_base` (env, read-only)
    │                                 + `f2b` block (live jail values via socket, 3 s timeout, outside cfgMu)
    ├─ POST /api/settings          → partial update; body capped at 1 MB via MaxBytesReader. The 14
    │                                 plain-string notify channel fields are driven by ONE table:
    │                                 `notifySettingJSONKeys` (api.go, JSON key → DB key) paired with
    │                                 `config.NotifySettingKeys()` (DB key → *Config field) — add a channel by
    │                                 extending both maps + notify.New; GET/POST/env-lock pick it up automatically.
    │                                 f2b_maxretry / f2b_bantime_secs / f2b_findtime_secs are applied to the
    │                                 RUNNING fail2ban FIRST (502 + no DB write when unreachable/apply fails);
    │                                 env-pinned notify fields are never written to the DB. `ignore_ips` is
    │                                 validated with responder.ParseAllowlist (400 on bad entry), persisted as
    │                                 `security.ignore_ips`, and applied live via Allowlist.SetExtra
    ├─ POST /api/notify/test       → Dispatcher.SendTest: synchronous, BYPASSES rules, returns real delivery errors (502 on failure)
    └─ GET /               → embed.FS (web/dist/index.html, sidebar dashboard)

All responses pass through `securityHeaders` (outermost middleware: nosniff, X-Frame-Options DENY,
no-referrer, and a CSP that allows inline script/style — single-file dashboard — but blocks all
external origins). Failed basic-auth attempts with credentials present sleep `authFailureDelay` (300 ms)
— stateless brute-force damping; the credential-less browser challenge round-trip is not delayed.
`/api/stream` clears the per-connection write deadline via `http.NewResponseController` — without
this the server-wide `WriteTimeout` (60 s) kills every SSE stream after a minute. `clientIP(r)`
trusts the last X-Forwarded-For hop only when the direct peer is loopback/private (local reverse
proxy); used for ban anti-self-lockout and audit logging.

publish hook (called per event in pipeline):
    srv.PublishEvent(ev)   → SSE hub
    srv.NotifyEvent(ev)    → current Dispatcher (swappable at runtime)
    srv.AutoBanEvent(ev)   → auto-ban if threshold exceeded (background goroutine, per-IP cooldown via sync.Map)
```

**Key interfaces** — all wired via constructors in `main.go`, no globals:
- `ingest.Source` — `Start(ctx, chan<- string)` + `Info() SourceInfo` — `fileSource` (nxadm/tail) and `journaldSource` (journalctl subprocess). The pipeline wraps each source in a retry loop (exponential backoff 1s→30s) so a transient journald restart does not permanently stop ingestion, and tracks per-source health (`Pipeline.SourceStatuses()` → wired into `/api/health` via `api.Server.SetSourceStatusFunc`). `fileSource.Start` pre-flight-opens the file and returns a loud, retried error on missing file or permission denied — a container that cannot read auth.log (640 root:adm, no group_add) must show up in logs and the UI banner, not as a silently empty dashboard. tail's internal messages go to slog via `newTailLogger` (never `tail.DiscardingLogger`). Use `NewFileSource(path)` for auth/nginx logs (starts from end of file); use `NewFileSourceFromStart(path)` for fail2ban.log so ban state is reconstructed from full history on every restart.
- `f2b.Manager` (`internal/f2b`) — pure-Go client for the fail2ban command socket (`LOGFORT_FAIL2BAN_SOCKET`, default `/var/run/fail2ban/fail2ban.sock`): requests are protocol-0 pickles (list of strings + `<F2B_END_COMMAND>`), responses are decoded by a minimal hand-rolled unpickler (`pickle.go`, protocols 0–5 subset incl. pickled exceptions). Falls back to executing `fail2ban-client` when the socket is absent (bare-metal). Methods: `Ping / GetJail / SetJail / BanIP / UnbanIP / Banned`. `SetJail` uses runtime `set <jail> …` commands — they do NOT survive a fail2ban restart, which is why `main.go` runs `runF2BEnforce` (initial retries 0s/15s/45s, then every 10 min; reads `f2b.*` keys from the settings table, no-ops when they're absent or live values already match). `UnbanIP`/`BanIP` treat "not banned"/"already banned" errors as success (idempotent reconciliation). The socket is root-only — install.sh runs the container as root when fail2ban control is enabled.
- `store.Store` — `InsertEvent / ListEvents / GetStats / GetMapPoints / ListBans / BanIP / UnbanIP / DeleteOldEvents / CountIPEvents / GetSetting / SetSetting / SetSettings / GetAllSettings / Ping / Backup`. `Ping` runs `SELECT 1` (health probe); `Backup(ctx, dstPath)` runs `VACUUM INTO ?` — dstPath must not exist, safe under concurrent writes.
- `geo.Looker` — `Lookup(ip) Info` — `geo.DB` (mmdb) or `geo.NoopLooker{}` (no file)
- `responder.Responder` — `Ban / Unban / List / Name` — `NftablesResponder`, `Fail2BanResponder` (thin wrapper over `f2b.Manager` — works inside Docker with the socket mounted, no Python needed), or `NoopResponder`
- `responder.Allowlist` — base entries (env `LOGFORT_IGNORE_IPS`, immutable) + extra entries swappable at runtime via `SetExtra([]string) error` (RWMutex-protected; invalid input leaves the previous extra set intact). `main.go` applies `cfg.ExtraIgnoreIPs` (DB key `security.ignore_ips`, overlaid by `OverlaySettings`) after `responder.New`; POST /api/settings re-applies on save.
- `notify.Notifier` — `Send(ctx, Message) error` — `webhookNotifier`, `telegramNotifier`, `discordNotifier`, `slackNotifier`, `ntfyNotifier`, `gotifyNotifier`, `emailNotifier` (SMTP; port 465 = implicit TLS, otherwise STARTTLS when offered; bare host defaults to :587; connection deadline from ctx bounds the whole session). Slack/Gotify go through `postJSON`/`postJSONHdr` (Gotify token in `X-Gotify-Key` header); ntfy POSTs the raw body with Title/Priority/Tags headers (`sanitizeHeaderValue` strips CR/LF). Gotify needs url+token, email needs host+from+to, ntfy needs url (token optional).
- `Pipeline.SetGeo` / `Pipeline.SetPublishHook` — optional hooks set in main; hook calls `srv.PublishEvent(ev)` (SSE hub) and `srv.NotifyEvent(ev)` (not `dispatcher.Notify` directly) so the dispatcher can be swapped at runtime
- `api.Server.SetCounterFunc(pipeline.Counters)` — wires parsed/unparsed counters into `/api/health`
- `api.Server.SetDispatcher(d)` — preferred way to wire a `*notify.Dispatcher`; calls `Stop()` on the previous dispatcher before replacing it. Use `SetNotifyFunc(fn)` only in tests (does not call Stop).
- `api.Server.SetEnvNotifyConfig(config.Config)` — must be called in `main.go` with the pre-`OverlaySettings` config so that POST /api/settings never overwrites fields set by env vars at runtime. `Server.cfgMu` (RWMutex) protects runtime-mutable notify **and** auto-ban/retention fields of `cfg`; always hold it when reading or writing those fields in handlers.
- `api.Server.SetGeoIPEnabled(bool)` — call in `main.go` after `geo.Open()` so `/api/system` can report geoip status.
- `api.Server.NotifyEvent(ev)` — mutex-protected dispatch through the current notifyFn; safe to call from any goroutine.
- `api.Server.AutoBanEvent(ev)` — checks auto-ban threshold and bans via responder in a background goroutine; uses `autoBanCooldown sync.Map` (IP → last-ban time, set via `LoadOrStore` before spawning) to prevent duplicate bans within the window. On transient failure (DB error or firewall error) the cooldown is cleared so the next event can retry. A semaphore (`autoBanSem`, capacity 100) caps concurrent background goroutines. Only fires when `cfg.AutoBanEnabled && cfg.ResponderEnabled`, and only for **primary attempt event types** (`failed_password`, `http_auth_fail`, `max_auth`) — the same set `CountIPEvents` counts. Normalized IP (via `normalizeIP`) is used throughout so IPv4-mapped IPv6 is handled consistently. `Server.shutCtx` (cancelled in `Close()`) is used as the parent context for background ban operations so they respect graceful shutdown.
- `api.Server.SetF2BManager(m)` — wires the `f2b.Manager` for the settings API; `main.go` only calls it when `Available()` (socket or CLI present), so `s.f2bMgr == nil` means "no fail2ban integration".

**parse package** — stateless, regexes compiled at init. `ParseLine` dispatches in this order:
1. fail2ban prefix (`YYYY-MM-DD HH:MM:SS,ms fail2ban`) → `parseFail2BanLine`
2. nginx error.log prefix (`YYYY/MM/DD HH:MM:SS [`) → `parseNginxErrorLine` (auth failures only)
3. nginx access.log prefix (`IP - user [ts]`) → `parseNginxAccessLine` (401 responses only)
4. syslog/RFC3339 prefix with `proc=sshd` or `proc=sshd-session` → `parseSSHDLine` against `sshdPatterns` (`sshd-session` is used by OpenSSH 9+ / Debian 13)

`ErrNoMatch` = line is silently ignored (counted in `unparsed` counter). Nginx events get `source="nginx"`, `event_type="http_auth_fail"`. `failed_password` and `accepted` patterns also match `keyboard-interactive/pam` (sshd's wording when PAM handles the password prompt).

**Attempt-counting rule:** one wrong password against an unknown user makes sshd log up to four lines (`Invalid user`, `pam_unix … authentication failure`, `Failed password`, `Connection closed … [preauth]`) — all four are parsed and stored as separate events for visibility, but only **primary attempt types** (`failed_password`, `http_auth_fail`, `max_auth`) count toward auto-ban and the `threshold:` notify rule (see `CountIPEvents` and `AutoBanEvent`). Counting the auxiliary lines would triple-count a single attempt.

**Timezone rule:** zone-less timestamps (traditional syslog, fail2ban, nginx error.log) are parsed in `time.Local` and converted to UTC — syslog writes host-local time. Deployments must mount `/etc/localtime:ro` into the container (install.sh and docker-compose.yml do this) so container-local == host-local. Parsing them as UTC on a host west of UTC made every live event look pre-startup, and the dispatcher's replay guard silently dropped **all** notifications.

**store package** — single writer (`SetMaxOpenConns(1)`). `New()` creates the parent directory of the DB path (plain paths only, not `:memory:`/`file:` DSNs). Migrations in `internal/store/migrations/*.sql`, embedded via `//go:embed`, applied idempotently at startup. The migration runner splits each file on `;` and executes statements individually (`splitSQL` helper in sqlite.go). Active pragmas: `WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `cache_size=-65536` (64 MB), `temp_store=MEMORY`; `PRAGMA optimize` runs on `Close()`. Key indexes: `idx_events_ts_type(ts, event_type)` and `idx_events_ip_ts(ip, ts)` cover the dominant stats query pattern. `GetStats` builds WHERE clause dynamically via `windowToSince()` → `(since int64, bucketSecs int64)`; bucket sizes: 1h→300s, 6h→1800s, 24h→3600s, 7d/30d/all→86400s, and the chosen size is returned as `bucket_secs` in the stats JSON (UI uses it for the timeline). `store.IsValidWindow` lets handlers return 400 for bad windows vs 500 for DB errors. `InsertEvent` uses `INSERT OR IGNORE` against a `UNIQUE INDEX ON events(ts, ip, COALESCE(port,-1), event_type)` — duplicate rows return `store.ErrDuplicate` (callers must check `errors.Is(err, store.ErrDuplicate)` and skip side-effects). It also mirrors `ban`/`unban` events into the `bans` table in the same call. The `unban` mirror uses `AND source='fail2ban'` in the WHERE clause so that a replayed historical fail2ban unban can only deactivate fail2ban-created ban rows — never a ban placed manually via POST /api/ban. All list/slice return values are always `[]T{}` not `nil` (important for JSON `[]` vs `null`). `BanIP` uses `INSERT ... SELECT ... WHERE NOT EXISTS (active ban)` to avoid duplicate active bans. `CountIPEvents(ctx, ip, since)` counts **primary attempt events only** (`IN ('failed_password','http_auth_fail','max_auth')`) — auxiliary lines (`invalid_user`, `pam_failure`, `disconnect_preauth`) belong to the same attempt and would double/triple-count it; accepted logins never count. `DeleteOldEvents` also prunes **inactive** ban rows older than the cutoff (active bans are never touched). The `settings` table (migration 005) is a generic key-value store (`key TEXT PRIMARY KEY, value TEXT`) used by the UI to persist notification config; `GetAllSettings` is called at startup in `main.go` and the result is passed to `cfg.OverlaySettings` — env vars take priority over DB values.

**geo package** — wraps `oschwald/maxminddb-golang`. Supports GeoLite2-City and DB-IP Lite formats (same mmdb binary format). Any lookup error returns empty `Info{}` — never propagates to caller.

**web embed** — `web/webui.go` (package `webui`) holds `//go:embed dist`. API package imports it and serves via `fs.Sub(webui.FS, "dist")`. Frontend is vanilla HTML/JS (no build step). Vendor assets (`leaflet.min.js/css`, `topojson-client.min.js`, `countries-110m.json`) are committed to `web/dist/` and explicitly un-ignored in `.gitignore`. Layout: left sidebar (220 px) with five sections — Dashboard, Events, Map, Bans, Settings. The sidebar and mobile tab bar are **theme-aware** via dedicated `--sb-*` CSS variables (dark keeps Nord Polar Night; light is white) — never hardcode sidebar colors. Attack-map colors come from `--map-*` variables; country polygons are Leaflet layer styles (not CSS), so `applyTheme` calls `restyleMap()` (`countriesLayer`/`meshLayer.setStyle` with values read from CSS vars) and `redrawTimeline()` (canvas samples colors at draw time; last data kept in `lastTimeline`). Mobile breakpoint is `@media (max-width: 700px)`: sidebar hides, a bottom tab bar appears, and table columns are hidden via CSS `nth-child`. Theme toggle (sun/moon icon) at the bottom of the sidebar; theme (`dark`/`light`) persisted in `localStorage` key `logfort-theme`; CSS variables live under `[data-theme="dark"]` / `[data-theme="light"]` on `<html>`. All sections except the dashboard are flex columns — `switchSection` must show them with `display:flex`. `prependLiveEvent` must emit the same column count as `eventsTable()` (extra actions cell when `responderEnabled`). The Settings section has **three tabs**: **General** (system info read-only from `/api/system` + parsed/unparsed line counters from `/api/health` + DB size, data retention days, Database Backup card with a `/api/backup` download button; saves only `{retention_days}`), **Notifications** (Telegram/Discord/Webhook/Slack/ntfy/Gotify/Email cards driven by the `FIELD_IDS` map in `loadNotifySettings` — input id ↔ settings JSON key, one entry per field handles value fill + env-lock; alert rules picker with `threshold:N/dur` decomposition; saves only notify fields), and **Firewall** (responder info read-only, auto-ban toggle + threshold + window select hidden when `responder_enabled=false`, Allowlist card — read-only base chips from `ignore_ips_base` + textarea for extra entries, own Save button posting `{ignore_ips}` (commas/newlines both accepted, joined with commas), always visible — and manual ban/unban form; auto-ban save posts only `{autoban_enabled, autoban_threshold, autoban_window}`). `POST /api/settings` treats absent JSON keys as "don't change", so each tab/card saves independently without clobbering the others. Events section has client-side pagination (`eventsPage`, `eventsPageSize` JS state; prev/next buttons; 50/100/200 per-page selector), an event-type filter select, exact-match IP and username filter inputs (feeding `type`/`ip`/`user` query params via `eventsFilterParams()`), and a CSV button that opens `/api/events.csv` with the current filters; the Bans toolbar has a CSV button for `/api/bans.csv`. Every IP rendered in tables and top lists is wrapped in `.ip-link` with `onclick="filterByIP(ip)"` — jumps to Events pre-filtered to that IP (clears type/user filters). Timeline chart (`drawTimeline`) fills sparse API buckets with zero-count entries to cover the full window range — the API returns only non-empty buckets; the bucket size comes from the `bucket_secs` field of `/api/stats` (JS keeps a fallback map). Map section must be shown with `display:flex` (not `display:block`) so `#map-el { flex:1 }` gets a non-zero height. `handleMap` includes `home_lat`/`home_lon` in its JSON response when `cfg.HomeLat`/`cfg.HomeLon` are set; `loadMap` renders a green circle marker at those coordinates.

**responder package** — active firewall control. `New(cfg)` returns a `(Responder, *Allowlist, error)` triple; callers pass these into `api.Server.SetResponder`. The nftables backend lives in `nftables.go` (`//go:build linux`) with a stub in `nftables_stub.go` (`//go:build !linux`) — both export the same `newNftablesResponder` signature. `normalizeIP()` in api.go converts IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to plain IPv4 for reliable comparisons (including anti-self-lockout). Ban flow: `store.BanIP` first, then `responder.Ban`; on firewall failure, `store.UnbanIP` is called to rollback before returning HTTP 500. Unban is never rate-limited — only POST /api/ban uses `banLim` (10 rps burst 20; token bucket keeps **float64** tokens — integer math starves the bucket under sustained sub-token-interval load). At startup `main.go` runs `reconcileBans` for the nftables backend only: active DB bans with `source == responder.Name()` are re-applied to the firewall, because nftables sets are kernel-memory-only and empty after a host reboot (fail2ban persists its own bans; source='fail2ban' rows are skipped).

**notify package** — `notify.New(cfg, st)` returns a `*Dispatcher` (nil if no notifiers or rules configured — nil-safe to call). Returns `(nil, err)` only on bad rule syntax. Rules parsed from `LOGFORT_NOTIFY_RULES` or the `settings` DB table: `accepted_login`, `ban`, `new_country`, `threshold:N/dur` (e.g. `threshold:100/1h`). `Dispatcher.Notify(ev)` fires a background goroutine per event using an internal context (cancelled by `Dispatcher.Stop()`), evaluates all rules, calls all configured notifiers. The `new_country` rule tracks seen countries in an in-memory `sync.Map` (resets on restart). The threshold rule uses `store.CountIPEvents` and has per-IP cooldown equal to the window to avoid alert spam. `Dispatcher.startedAt` is set to `time.Now()` in `New()` — events with `TS` older than `startedAt - 1 minute` are silently dropped in `dispatch()`, which prevents an alert flood when fail2ban.log is replayed from the beginning on startup. Tests that construct `&Dispatcher{}` directly get a zero `startedAt`, which passes all events through. POST /api/settings validates the proposed config with `notify.New` before touching the DB (bad rules → HTTP 400, no DB write); on success it swaps the live Dispatcher via `srv.SetDispatcher`, which calls `Stop()` on the old one — no restart needed. Env-var-set notify fields are never overridden by the UI: `Server.envCfg` (set via `SetEnvNotifyConfig`) gates which fields `handlePostSettings` may mutate at runtime. `Dispatcher.SendTest(ctx)` (nil-safe, returns error on nil) delivers a fixed test message synchronously to every notifier **bypassing rules** — POST /api/notify/test uses it so the user gets real delivery feedback instead of a blind "sent". All three notifiers go through `postJSON` (http.go): it retries once on 429/5xx honoring `retry_after` from the body (capped at 5 s), drains bodies for keep-alive reuse, and returns up to 512 bytes of the response for error messages. The Telegram notifier additionally parses `{"ok":bool,"description":...}` — the description ("chat not found", "bot was blocked by the user") is surfaced in the error. `notify.New` trims whitespace from all tokens/URLs (a trailing newline in an env var silently breaks Telegram). The `telegramNotifier.apiBase` field exists so tests can point it at an httptest server.

## Configuration (env vars)

| Variable | Default | Notes |
|---|---|---|
| `LOGFORT_LISTEN` | `127.0.0.1:8080` | HTTP bind address |
| `LOGFORT_BACKEND` | `file` | Log backend: `file` or `journald` |
| `LOGFORT_LOG_PATHS` | `/host/auth.log` | Comma-separated log paths — sshd, nginx error.log, nginx access.log all auto-detected |
| `LOGFORT_JOURNALD_UNIT` | `ssh.service` | systemd unit to follow when `LOGFORT_BACKEND=journald`; requires `journalctl` in PATH |
| `LOGFORT_FAIL2BAN_LOG` | _(empty)_ | Optional fail2ban log, parsed as extra source |
| `LOGFORT_DB_PATH` | `/data/logfort.db` | SQLite database path |
| `LOGFORT_GEOIP_DB` | `/data/geo.mmdb` | GeoIP mmdb path; skipped if missing |
| `LOGFORT_RETENTION_DAYS` | `90` | Events older than N days are purged daily |
| `LOGFORT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOGFORT_HOME_LAT` / `_LON` | _(unset)_ | Optional home-marker on the attack map |
| `LOGFORT_AUTH_ENABLED` | `false` | Enable HTTP Basic Auth (all routes except `/api/health`); requires both `_USER` and `_PASS` to be non-empty or startup fails |
| `LOGFORT_AUTH_USER` / `_PASS` | _(empty)_ | Basic auth credentials (both required when auth is enabled) |
| `LOGFORT_RESPONDER_ENABLED` | `false` | Enable active banning |
| `LOGFORT_RESPONDER_BACKEND` | `nftables` | `nftables` or `fail2ban` |
| `LOGFORT_NFT_TABLE` | `inet filter` | nftables table spec (`family name`) |
| `LOGFORT_NFT_SET` | `logfort_block` | nftables set name (must exist or be created) |
| `LOGFORT_FAIL2BAN_JAIL` | `sshd` | fail2ban jail name |
| `LOGFORT_FAIL2BAN_SOCKET` | `/var/run/fail2ban/fail2ban.sock` | fail2ban command socket; enables `internal/f2b` (UI jail settings + socket-based responder) |
| `LOGFORT_IGNORE_IPS` | RFC-1918 + loopback | Comma-separated CIDRs/IPs never banned |
| `LOGFORT_NOTIFY_WEBHOOK_URL` | _(empty)_ | Generic webhook (POST JSON); overrides UI setting |
| `LOGFORT_NOTIFY_TELEGRAM_TOKEN` / `_CHAT_ID` | _(empty)_ | Telegram bot notify; overrides UI setting |
| `LOGFORT_NOTIFY_DISCORD_URL` | _(empty)_ | Discord webhook notify; overrides UI setting |
| `LOGFORT_NOTIFY_SLACK_URL` | _(empty)_ | Slack incoming webhook; overrides UI setting |
| `LOGFORT_NOTIFY_NTFY_URL` / `_TOKEN` | _(empty)_ | ntfy topic URL + optional Bearer token; overrides UI setting |
| `LOGFORT_NOTIFY_GOTIFY_URL` / `_TOKEN` | _(empty)_ | Gotify server URL + app token (both required); overrides UI setting |
| `LOGFORT_NOTIFY_SMTP_HOST` | _(empty)_ | SMTP `host:port` (bare host → :587; 465 = implicit TLS, else STARTTLS); overrides UI setting |
| `LOGFORT_NOTIFY_SMTP_USER` / `_PASS` | _(empty)_ | SMTP auth (optional; PLAIN, refused over plaintext to non-localhost) |
| `LOGFORT_NOTIFY_SMTP_FROM` / `_TO` | _(empty)_ | Sender + comma-separated recipients (both required to enable email) |
| `LOGFORT_NOTIFY_RULES` | _(empty)_ | Comma-separated: `accepted_login`, `ban`, `new_country`, `threshold:N/dur`; overrides UI setting |

Notify settings can also be configured via the Settings UI and are persisted in the `settings` SQLite table. Env vars always win over DB values (`config.OverlaySettings` only fills fields that are empty after env loading).

**UI-only settings** (no env vars; always overlaid from DB, DB wins):

| DB key | Type | Default | Notes |
|---|---|---|---|
| `general.retention_days` | int | 90 | Overrides `LOGFORT_RETENTION_DAYS`; `runRetention` reads from DB on each tick |
| `autoban.enabled` | bool | false | Requires `LOGFORT_RESPONDER_ENABLED=true` to take effect |
| `autoban.threshold` | int | 50 | Primary failed attempts per window before auto-ban fires |
| `autoban.window` | duration string | `1h` | Any value accepted by `time.ParseDuration` |
| `f2b.maxretry` | int | _(unset)_ | fail2ban jail maxretry; applied via socket on save + enforced by `runF2BEnforce` |
| `f2b.bantime` | int (seconds) | _(unset)_ | fail2ban jail bantime |
| `f2b.findtime` | int (seconds) | _(unset)_ | fail2ban jail findtime |
| `security.ignore_ips` | comma-separated IPs/CIDRs | _(unset)_ | Extra allowlist entries, unioned with `LOGFORT_IGNORE_IPS`; validated with `responder.ParseAllowlist`, applied live via `Allowlist.SetExtra` |

`config.Config` fields: `AutoBanEnabled`, `AutoBanThreshold`, `AutoBanWindow`, `ExtraIgnoreIPs`, `F2BMaxRetry`, `F2BBanTime`, `F2BFindTime` (int64 seconds; 0 = not managed). Unset `f2b.*` keys mean "never touch fail2ban" — `runF2BEnforce` exits its apply pass without any socket I/O.

## Adding a SQLite migration

1. Create `internal/store/migrations/NNN_description.sql` (e.g. `006_add_column.sql`; current latest is `005_settings.sql`).
2. Write idempotent SQL (`CREATE INDEX IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, etc.).
3. Multi-statement files are supported — the runner splits on `;` and executes each statement in its own `Exec` call within the transaction.
4. Already-applied versions (tracked in `schema_migrations`) are skipped on next startup.
5. `go test -race ./internal/store/...` — the store tests open an in-memory DB and run all migrations.

## Adding a parser pattern

**sshd pattern:**
1. Add raw fixture line to `testdata/auth_debian.log` or `testdata/secure_rhel.log`.
2. Add test case in `internal/parse/parser_test.go`.
3. Add/extend regex in `sshdPatterns` slice in `internal/parse/parser.go`.
4. `go test -race ./internal/parse/...`

**nginx pattern:**
Same steps, but add the regex to `nginxAuthPatterns` (error.log auth messages) or extend `reNginxAccess` (access.log). Fixture file: `testdata/nginx_error.log` or `testdata/nginx_access.log`.

**journald note:** `journaldSource` reconstructs RFC3339 syslog lines (`"2024-01-15T10:30:00Z host sshd[pid]: message"`) from journald JSON so that `parse.ParseLine` handles them without changes. `MESSAGE` may be a JSON string or a JSON array of byte values (non-UTF-8) — `decodeJournaldMessage` in `internal/ingest/journald.go` handles both.

## Deploying

`install.sh` — host-side setup script (not run inside the container). Detects distro, optionally installs fail2ban, then:

- **fail2ban jail tuning** — prompts for attempts-before-ban (default 3) and ban hours (default 1), writes `/etc/fail2ban/filter.d/logfort-sshd.conf` (matches ONLY `Failed password|keyboard-interactive` lines — the stock sshd filter also matches `Invalid user` and pam_unix lines, so with unknown usernames every wrong password produced ≥2 matches and maxretry=3 banned after 2 real attempts) and `/etc/fail2ban/jail.d/logfort.local` (`[sshd] filter=logfort-sshd maxretry=N findtime=10m bantime=Hh`; `jail.d/*.local` has the highest precedence). Both files are managed and **overwritten** on re-run (after the prompt). After restarting fail2ban the script **verifies** the effective values via `fail2ban-client get sshd maxretry` and warns loudly if fail2ban failed to come back up. The filter's `journalmatch` OR's `sshd.service`/`ssh.service`/`_COMM=sshd`/`_COMM=sshd-session` so the systemd backend works on Debian, Ubuntu and RHEL.
- **fail2ban web-UI control (optional)** — mounts `/var/run/fail2ban` into the container, sets `user: "0:0"` (the socket is root-only), and sets `LOGFORT_RESPONDER_ENABLED=true` + `LOGFORT_RESPONDER_BACKEND=fail2ban` so manual bans and the Settings → Firewall jail editor work out of the box.
- **log access** — mounts `/var/log` as a DIRECTORY (`/var/log:/host/log:ro`), never individual files: a single-file bind mount pins the inode and goes stale after the first logrotate. When not running as root, adds `group_add` with the auth log's GID (`stat -c %g`, Debian/Ubuntu `adm`); if the log is not group-readable (RHEL `/var/log/secure` is 600 root:root) it falls back to `user: "0:0"` with a warning. Files outside `/var/log` are mounted individually with a rotation warning.

Then asks `file` vs `journald` backend, auto-detects the auth log path (file) or prompts for the systemd unit (journald), and generates a ready-to-run `docker-compose.yml` in the install directory (default `/opt/logfort`). For the journald backend the compose mounts `/run/log/journal`, `/var/log/journal`, `/run/systemd/journal` and `/etc/machine-id` from the host, and adds the host's `systemd-journal` GID via `group_add`. Always sets `LOGFORT_LISTEN=0.0.0.0:8080` in the generated compose (required inside Docker — binding to `127.0.0.1` inside the container blocks Docker's bridge proxy) and mounts `/etc/localtime:ro` (both backends) so the parser's local-time interpretation of zone-less log timestamps matches the host. The `data/` directory is `chmod 777` so the non-root `logfort` container user can write the SQLite database. Files written into `data/` by root (e.g. geo.mmdb downloaded during install) must be `chmod 644` — otherwise the container user gets `permission denied` and GeoIP silently falls back to NoopLooker. GeoIP download falls back to the previous month when the current month's DB-IP file is not published yet. All `read` prompts use a `read_tty` helper (`read -r VAR </dev/tty`) so the script works when piped via `curl | bash`. The container image is `debian:bookworm-slim` with `apt install systemd` (provides `journalctl`); Alpine was dropped because `systemd` is not packaged for Alpine stable.

```bash
sudo bash install.sh [--dir /opt/logfort] [--image ghcr.io/unwinds/logfort:latest]
```

## Releasing

```bash
git tag v1.0.0 && git push origin v1.0.0
```

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which runs tests, then `goreleaser` (config in `.goreleaser.yaml`). GoReleaser:
- Cross-compiles `linux/{amd64,arm64,armv7}` binaries with `-X main.version=<tag>`
- Builds Docker images per-arch using `Dockerfile.release` (copies pre-built binary; no Go toolchain)
- Pushes multi-arch manifests `ghcr.io/unwinds/logfort:<tag>` and `:latest` to GHCR
- Creates a GitHub Release with binaries, checksums, and grouped changelog

For local Docker builds use `Dockerfile` (full multi-stage build with Go toolchain); `Dockerfile.release` is for goreleaser only.

## Conventions

- Commits: Conventional Commits — `feat(pkg):`, `fix(pkg):`, `chore:`, `test:`, `docs:`.
- Language: communicate with the user in **Russian**; code, identifiers, config keys, comments — **English**.
- `context.Context` threaded through all store and ingest calls.
- Structured logging via `log/slog` (JSON handler, no `fmt.Print*` in runtime paths).
- Errors wrapped with `%w`; no `panic` outside init/startup.
- `responder` touches the host firewall — always check `IGNORE_IPS` and anti-self-lockout before any ban.
- `notify.Dispatcher` is nil-safe — `New` returns nil (not error) when no notifiers/rules configured; callers must not crash on nil. `Dispatcher.Stop()` is also nil-safe. Always swap via `srv.SetDispatcher` (not `SetNotifyFunc`) when replacing a live Dispatcher so `Stop()` is called on the old one.
- Basic auth exempts `/api/health` — Docker `HEALTHCHECK` must remain credential-free. `/metrics` is NOT exempt (Prometheus scrape configs support basic_auth).
- Shutdown order in `main.go` matters: `srv.Shutdown()` (closes SSE hub, idempotent via `sync.Once` in Hub) → `httpSrv.Shutdown(ctx)` → `srv.Close()`. Skipping the first step makes every shutdown wait the full 10 s timeout while open SSE connections linger.
- `runRetention` executes one cleanup pass at startup before entering the 24 h ticker loop — hosts that restart the container daily would otherwise never purge.
- `store.ErrDuplicate` is returned by `InsertEvent` when the row already exists; callers (pipeline, tests) must check for it with `errors.Is` and skip publish/notify side-effects rather than treating it as a fatal error. `BanIP` uses `INSERT … SELECT … WHERE NOT EXISTS` — it returns `nil` (0 rows affected, no error) when a ban already exists; any non-nil error from `BanIP` is a genuine DB failure.
- `store.SetSettings(ctx, map[string]string)` atomically persists multiple key-value pairs in a single SQLite transaction; use it instead of calling `SetSetting` in a loop when saving multi-field settings to avoid partial-write inconsistency on DB errors.
- When adding new methods to `store.Store` interface, also add stub implementations to `mockStore` in `internal/api/api_test.go`, `stubStore` in `internal/notify/dispatcher_test.go`, and `stubStore` in `internal/ingest/pipeline_test.go`. When changing `ingest.Source`, update `fakeSource` in `internal/ingest/pipeline_test.go` (implements `Info()`).
- `internal/f2b` has no external dependencies — the pickle codec is hand-rolled and tested against fixed byte fixtures plus a fake unix-socket server (`f2b_test.go`); tests skip automatically where unix sockets are unavailable.
