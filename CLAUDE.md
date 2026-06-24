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
    ├─ GET /api/system             → read-only runtime config (backend, paths, geoip, responder, auth)
    ├─ POST /api/ban|unban  (403 when responder disabled)
    │     └─ on success: calls srv.NotifyEvent (mutex-protected, swappable at runtime)
    ├─ GET  /api/settings          → all UI-configurable settings (notify + retention + autoban)
    ├─ POST /api/settings          → partial update via pointer fields; persist to DB; rebuild Dispatcher
    ├─ POST /api/notify/test       → fire test event through current Dispatcher
    └─ GET /               → embed.FS (web/dist/index.html, sidebar dashboard)

publish hook (called per event in pipeline):
    srv.PublishEvent(ev)   → SSE hub
    srv.NotifyEvent(ev)    → current Dispatcher (swappable at runtime)
    srv.AutoBanEvent(ev)   → auto-ban if threshold exceeded (background goroutine, per-IP cooldown via sync.Map)
```

**Key interfaces** — all wired via constructors in `main.go`, no globals:
- `ingest.Source` — `Start(ctx, chan<- string)` — `fileSource` (nxadm/tail) and `journaldSource` (journalctl subprocess). The pipeline wraps each source in a retry loop (exponential backoff 1s→30s) so a transient journald restart does not permanently stop ingestion. Use `NewFileSource(path)` for auth/nginx logs (starts from end of file); use `NewFileSourceFromStart(path)` for fail2ban.log so ban state is reconstructed from full history on every restart.
- `store.Store` — `InsertEvent / ListEvents / GetStats / GetMapPoints / ListBans / BanIP / UnbanIP / DeleteOldEvents / CountIPEvents / GetSetting / SetSetting / GetAllSettings`
- `geo.Looker` — `Lookup(ip) Info` — `geo.DB` (mmdb) or `geo.NoopLooker{}` (no file)
- `responder.Responder` — `Ban / Unban / List / Name` — `NftablesResponder`, `Fail2BanResponder`, or `NoopResponder`
- `notify.Notifier` — `Send(ctx, Message) error` — `webhookNotifier`, `telegramNotifier`, `discordNotifier`
- `Pipeline.SetGeo` / `Pipeline.SetPublishHook` — optional hooks set in main; hook calls `srv.PublishEvent(ev)` (SSE hub) and `srv.NotifyEvent(ev)` (not `dispatcher.Notify` directly) so the dispatcher can be swapped at runtime
- `api.Server.SetCounterFunc(pipeline.Counters)` — wires parsed/unparsed counters into `/api/health`
- `api.Server.SetDispatcher(d)` — preferred way to wire a `*notify.Dispatcher`; calls `Stop()` on the previous dispatcher before replacing it. Use `SetNotifyFunc(fn)` only in tests (does not call Stop).
- `api.Server.SetEnvNotifyConfig(config.Config)` — must be called in `main.go` with the pre-`OverlaySettings` config so that POST /api/settings never overwrites fields set by env vars at runtime. `Server.cfgMu` (RWMutex) protects runtime-mutable notify **and** auto-ban/retention fields of `cfg`; always hold it when reading or writing those fields in handlers.
- `api.Server.SetGeoIPEnabled(bool)` — call in `main.go` after `geo.Open()` so `/api/system` can report geoip status.
- `api.Server.NotifyEvent(ev)` — mutex-protected dispatch through the current notifyFn; safe to call from any goroutine.
- `api.Server.AutoBanEvent(ev)` — checks auto-ban threshold and bans via responder in a background goroutine; uses `autoBanCooldown sync.Map` (IP → last-ban time) to prevent duplicate bans within the window. Only fires when `cfg.AutoBanEnabled && cfg.ResponderEnabled`.

**parse package** — stateless, regexes compiled at init. `ParseLine` dispatches in this order:
1. fail2ban prefix (`YYYY-MM-DD HH:MM:SS,ms fail2ban`) → `parseFail2BanLine`
2. nginx error.log prefix (`YYYY/MM/DD HH:MM:SS [`) → `parseNginxErrorLine` (auth failures only)
3. nginx access.log prefix (`IP - user [ts]`) → `parseNginxAccessLine` (401 responses only)
4. syslog/RFC3339 prefix with `proc=sshd` or `proc=sshd-session` → `parseSSHDLine` against `sshdPatterns` (`sshd-session` is used by OpenSSH 9+ / Debian 13)

`ErrNoMatch` = line is silently ignored (counted in `unparsed` counter). Nginx events get `source="nginx"`, `event_type="http_auth_fail"`.

**store package** — single writer (`SetMaxOpenConns(1)`). Migrations in `internal/store/migrations/*.sql`, embedded via `//go:embed`, applied idempotently at startup. The migration runner splits each file on `;` and executes statements individually (`splitSQL` helper in sqlite.go). Active pragmas: `WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `cache_size=-65536` (64 MB), `temp_store=MEMORY`; `PRAGMA optimize` runs on `Close()`. Key indexes: `idx_events_ts_type(ts, event_type)` and `idx_events_ip_ts(ip, ts)` cover the dominant stats query pattern. `GetStats` builds WHERE clause dynamically via `windowToSince()` → `(since int64, bucketSecs int64)`. `InsertEvent` uses `INSERT OR IGNORE` against a `UNIQUE INDEX ON events(ts, ip, COALESCE(port,-1), event_type)` — duplicate rows return `store.ErrDuplicate` (callers must check `errors.Is(err, store.ErrDuplicate)` and skip side-effects). It also mirrors `ban`/`unban` events into the `bans` table in the same call. The `unban` mirror uses `AND source='fail2ban'` in the WHERE clause so that a replayed historical fail2ban unban can only deactivate fail2ban-created ban rows — never a ban placed manually via POST /api/ban. All list/slice return values are always `[]T{}` not `nil` (important for JSON `[]` vs `null`). `BanIP` uses `INSERT ... SELECT ... WHERE NOT EXISTS (active ban)` to avoid duplicate active bans. `CountIPEvents(ctx, ip, since)` is used by the notify threshold rule. The `settings` table (migration 005) is a generic key-value store (`key TEXT PRIMARY KEY, value TEXT`) used by the UI to persist notification config; `GetAllSettings` is called at startup in `main.go` and the result is passed to `cfg.OverlaySettings` — env vars take priority over DB values.

**geo package** — wraps `oschwald/maxminddb-golang`. Supports GeoLite2-City and DB-IP Lite formats (same mmdb binary format). Any lookup error returns empty `Info{}` — never propagates to caller.

**web embed** — `web/webui.go` (package `webui`) holds `//go:embed dist`. API package imports it and serves via `fs.Sub(webui.FS, "dist")`. Frontend is vanilla HTML/JS (no build step). Vendor assets (`leaflet.min.js/css`, `topojson-client.min.js`, `countries-110m.json`) are committed to `web/dist/` and explicitly un-ignored in `.gitignore`. Layout: left sidebar (220 px) with five sections — Dashboard, Events, Map, Bans, Settings. Mobile breakpoint is `@media (max-width: 700px)`: sidebar hides, a bottom tab bar appears, and table columns are hidden via CSS `nth-child`. The Settings section has two tabs — **General** (system info read-only from `/api/system`, data retention days, auto-ban threshold/window toggle; auto-ban card hidden when responder disabled) and **Notifications** (Telegram/Discord/Webhook cards, alert rules picker with `threshold:N/dur` decomposition). `POST /api/settings` uses pointer fields — absent JSON fields are not overwritten, so General and Notifications tabs save independently without clobbering each other. Events section has client-side pagination (`eventsPage`, `eventsPageSize` JS state; prev/next buttons; 50/100/200 per-page selector). Timeline chart (`drawTimeline`) fills sparse API buckets with zero-count entries to cover the full window range — the API returns only non-empty buckets. Map section must be shown with `display:flex` (not `display:block`) so `#map-el { flex:1 }` gets a non-zero height.

**responder package** — active firewall control. `New(cfg)` returns a `(Responder, *Allowlist, error)` triple; callers pass these into `api.Server.SetResponder`. The nftables backend lives in `nftables.go` (`//go:build linux`) with a stub in `nftables_stub.go` (`//go:build !linux`) — both export the same `newNftablesResponder` signature. `normalizeIP()` in api.go converts IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to plain IPv4 for reliable comparisons (including anti-self-lockout). Ban flow: `store.BanIP` first, then `responder.Ban`; on firewall failure, `store.UnbanIP` is called to rollback before returning HTTP 500. Unban is never rate-limited — only POST /api/ban uses `banLim` (10 rps burst 20).

**notify package** — `notify.New(cfg, st)` returns a `*Dispatcher` (nil if no notifiers or rules configured — nil-safe to call). Returns `(nil, err)` only on bad rule syntax. Rules parsed from `LOGFORT_NOTIFY_RULES` or the `settings` DB table: `accepted_login`, `ban`, `new_country`, `threshold:N/dur` (e.g. `threshold:100/1h`). `Dispatcher.Notify(ev)` fires a background goroutine per event using an internal context (cancelled by `Dispatcher.Stop()`), evaluates all rules, calls all configured notifiers. The `new_country` rule tracks seen countries in an in-memory `sync.Map` (resets on restart). The threshold rule uses `store.CountIPEvents` and has per-IP cooldown equal to the window to avoid alert spam. `Dispatcher.startedAt` is set to `time.Now()` in `New()` — events with `TS` older than `startedAt - 1 minute` are silently dropped in `dispatch()`, which prevents an alert flood when fail2ban.log is replayed from the beginning on startup. Tests that construct `&Dispatcher{}` directly get a zero `startedAt`, which passes all events through. POST /api/settings validates the proposed config with `notify.New` before touching the DB (bad rules → HTTP 400, no DB write); on success it swaps the live Dispatcher via `srv.SetDispatcher`, which calls `Stop()` on the old one — no restart needed. Env-var-set notify fields are never overridden by the UI: `Server.envCfg` (set via `SetEnvNotifyConfig`) gates which fields `handlePostSettings` may mutate at runtime.

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
| `LOGFORT_IGNORE_IPS` | RFC-1918 + loopback | Comma-separated CIDRs/IPs never banned |
| `LOGFORT_NOTIFY_WEBHOOK_URL` | _(empty)_ | Generic webhook (POST JSON); overrides UI setting |
| `LOGFORT_NOTIFY_TELEGRAM_TOKEN` / `_CHAT_ID` | _(empty)_ | Telegram bot notify; overrides UI setting |
| `LOGFORT_NOTIFY_DISCORD_URL` | _(empty)_ | Discord webhook notify; overrides UI setting |
| `LOGFORT_NOTIFY_RULES` | _(empty)_ | Comma-separated: `accepted_login`, `ban`, `new_country`, `threshold:N/dur`; overrides UI setting |

Notify settings can also be configured via the Settings UI and are persisted in the `settings` SQLite table. Env vars always win over DB values (`config.OverlaySettings` only fills fields that are empty after env loading).

**UI-only settings** (no env vars; always overlaid from DB, DB wins):

| DB key | Type | Default | Notes |
|---|---|---|---|
| `general.retention_days` | int | 90 | Overrides `LOGFORT_RETENTION_DAYS`; `runRetention` reads from DB on each tick |
| `autoban.enabled` | bool | false | Requires `LOGFORT_RESPONDER_ENABLED=true` to take effect |
| `autoban.threshold` | int | 50 | Events per window before auto-ban fires |
| `autoban.window` | duration string | `1h` | Any value accepted by `time.ParseDuration` |

`config.Config` fields: `AutoBanEnabled`, `AutoBanThreshold`, `AutoBanWindow`.

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

`install.sh` — host-side setup script (not run inside the container). Detects distro, optionally installs fail2ban, asks whether to use the `file` or `journald` backend, auto-detects the auth log path (file backend) or prompts for the systemd unit (journald backend), and generates a ready-to-run `docker-compose.yml` in the install directory (default `/opt/logfort`). For the journald backend the compose mounts `/run/log/journal`, `/var/log/journal`, `/run/systemd/journal` and `/etc/machine-id` from the host, and adds the host's `systemd-journal` GID via `group_add` so the container user can read journal files. Always sets `LOGFORT_LISTEN=0.0.0.0:8080` in the generated compose (required inside Docker — binding to `127.0.0.1` inside the container blocks Docker's bridge proxy). The `data/` directory is `chmod 777` so the non-root `logfort` container user can write the SQLite database. Files written into `data/` by root (e.g. geo.mmdb downloaded during install) must be `chmod 644` — otherwise the container user gets `permission denied` and GeoIP silently falls back to NoopLooker. All `read` prompts use a `read_tty` helper (`read -r VAR </dev/tty`) so the script works when piped via `curl | bash`. The container image is `debian:bookworm-slim` with `apt install systemd` (provides `journalctl`); Alpine was dropped because `systemd` is not packaged for Alpine stable.

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
- Basic auth exempts `/api/health` — Docker `HEALTHCHECK` must remain credential-free.
- `store.ErrDuplicate` is returned by `InsertEvent` when the row already exists; callers (pipeline, tests) must check for it with `errors.Is` and skip publish/notify side-effects rather than treating it as a fatal error.
- When adding new methods to `store.Store` interface, also add stub implementations to `mockStore` in `internal/api/api_test.go`, `stubStore` in `internal/notify/dispatcher_test.go`, and `stubStore` in `internal/ingest/pipeline_test.go`.
