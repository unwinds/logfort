[English](README.md) · [Русский](README_RU.md)

# LogFort

[![CI](https://github.com/unwinds/logfort/actions/workflows/ci.yml/badge.svg)](https://github.com/unwinds/logfort/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/unwinds/logfort?color=58a6ff)](https://github.com/unwinds/logfort/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)

**Real-time SSH & nginx attack dashboard — self-hosted, one-command install, zero cloud.**

LogFort watches your auth logs and shows you a live browser dashboard: who is attacking, where from, what usernames they try, and a world map of attack origins — all without sending a single byte outside your server.

---

## Features

- 🔴 **Live event feed** — failed and accepted logins stream instantly via SSE, no polling
- 🗺️ **Offline attack map** — Leaflet + embedded GeoJSON, no external tile servers required
- 📊 **Stats & timeline** — top attacker IPs, usernames, countries; hourly/daily bar chart
- 🚫 **One-click banning** — active block via nftables or fail2ban, with full ban/unban history
- 🔔 **Notifications** — Telegram, Discord, or any webhook; rules: `accepted_login`, `ban`, `new_country`, `threshold:N/dur`
- 📋 **Events browser** — pagination, type/IP filters, one-click CSV export
- 📁 **Multiple log sources** — sshd `auth.log` / `secure`, nginx `error.log` + `access.log`, `fail2ban.log`, systemd journal
- 🔒 **HTTP Basic Auth** — optional, protects all routes except `/api/health`
- 🛡️ **Privacy-first** — zero outbound requests at runtime; GeoIP is a local `.mmdb` file
- 🤖 **Auto-ban** — automatically ban IPs that exceed a configurable threshold (events per time window); toggle and tune via the Settings UI without restart
- ⚙️ **Runtime settings UI** — configure notifications, auto-ban, and data retention in the browser, no restart needed
- 📈 **Prometheus metrics** — `/metrics` endpoint with parsed/unparsed counters and active-ban gauge

---

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/unwinds/logfort/main/install.sh | sudo bash
```

The script:
- Detects your distro (Debian/Ubuntu/RHEL/Rocky/Alma)
- Optionally installs Docker and fail2ban, and tunes the sshd jail with **exact attempt counting** — you choose attempts-before-ban and ban duration, and the values are verified after restart (the stock fail2ban filter counts extra log lines, banning after 2 of "3" attempts; LogFort ships a corrected filter)
- Optionally enables **fail2ban control from the web UI** (ban/unban IPs, change attempts/ban duration in Settings → Firewall)
- Lets you choose **file** backend (auth.log) or **journald** backend (systemd journal)
- Auto-detects your auth log path and sets up container access to it (log group / rotation-safe directory mount)
- Generates a ready-to-run `docker-compose.yml`
- Optionally pulls the image and starts the container

> **Flags:** `--dir /opt/logfort` and `--image ghcr.io/unwinds/logfort:latest`

After install, reach the dashboard via SSH tunnel:

```bash
ssh -L 8080:localhost:8080 user@yourserver
# Open http://localhost:8080
```

---

## Updating

```bash
cd /opt/logfort && docker compose pull && docker compose up -d
```

---

## GeoIP (optional, recommended)

Download a free [DB-IP Lite](https://db-ip.com/db/lite/city) database for the attack map — no account required:

```bash
curl -L "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz" \
  | gunzip > /opt/logfort/data/geo.mmdb
docker compose -f /opt/logfort/docker-compose.yml restart
```

Also supports MaxMind GeoLite2 City (same mmdb format).

---

## Manual Docker Compose

If you prefer not to use the install script:

```yaml
services:
  logfort:
    image: ghcr.io/unwinds/logfort:latest
    container_name: logfort
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      # Mount the directory, not the file — a single-file mount pins the inode
      # and stops receiving data after the first logrotate.
      - /var/log:/host/log:ro
      - /etc/localtime:/etc/localtime:ro   # host TZ — auth.log timestamps are local time
      - ./data:/data
    # auth.log is usually 640 root:adm — give the container the log group,
    # or it cannot read the file. Find the GID: stat -c %g /var/log/auth.log
    group_add:
      - "4"
    environment:
      - LOGFORT_LISTEN=0.0.0.0:8080
      - LOGFORT_LOG_PATHS=/host/log/auth.log
      - LOGFORT_DB_PATH=/data/logfort.db
    restart: unless-stopped
```

> **RHEL/Rocky/Alma:** `/var/log/secure` is `600 root:root` — replace `group_add` with `user: "0:0"` and set `LOGFORT_LOG_PATHS=/host/log/secure`.

If a log file cannot be read, the dashboard shows a red banner with the reason (also visible in `docker logs logfort`).

---

## Configuration

All settings are environment variables. Notification settings can also be changed at runtime via the Settings tab in the UI without restarting.

### Core

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_LISTEN` | `127.0.0.1:8080` | HTTP bind address (use `0.0.0.0:8080` inside Docker) |
| `LOGFORT_BACKEND` | `file` | Log backend: `file` or `journald` |
| `LOGFORT_LOG_PATHS` | `/host/auth.log` | Comma-separated log paths (sshd, nginx auto-detected by content) |
| `LOGFORT_JOURNALD_UNIT` | `ssh.service` | systemd unit to follow (journald backend only) |
| `LOGFORT_FAIL2BAN_LOG` | _(empty)_ | Optional fail2ban log — replayed from the beginning on each start |
| `LOGFORT_DB_PATH` | `/data/logfort.db` | SQLite database path |
| `LOGFORT_GEOIP_DB` | `/data/geo.mmdb` | GeoIP mmdb path; silently skipped if missing |
| `LOGFORT_RETENTION_DAYS` | `90` | Purge events older than N days |
| `LOGFORT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOGFORT_HOME_LAT` / `_LON` | _(empty)_ | Optional home-marker coordinates on the attack map |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_AUTH_ENABLED` | `false` | Enable HTTP Basic Auth (all routes except `/api/health`) |
| `LOGFORT_AUTH_USER` / `_PASS` | _(empty)_ | Credentials — both required when auth is enabled |

### Active Banning

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_RESPONDER_ENABLED` | `false` | Enable firewall integration |
| `LOGFORT_RESPONDER_BACKEND` | `nftables` | `nftables` or `fail2ban` |
| `LOGFORT_NFT_TABLE` | `inet filter` | nftables table (`family name`) |
| `LOGFORT_NFT_SET` | `logfort_block` | nftables set name (must exist) |
| `LOGFORT_FAIL2BAN_JAIL` | `sshd` | fail2ban jail name |
| `LOGFORT_FAIL2BAN_SOCKET` | `/var/run/fail2ban/fail2ban.sock` | fail2ban command socket (mount `/var/run/fail2ban` into the container) |
| `LOGFORT_IGNORE_IPS` | RFC-1918 + loopback | CIDRs/IPs that are never banned |

With the fail2ban socket mounted (`- /var/run/fail2ban:/var/run/fail2ban` + `user: "0:0"` — the socket is root-only), LogFort talks to fail2ban directly: manual ban/unban from the UI works through the `fail2ban` responder backend, and **Settings → Firewall** lets you change the jail's attempts-before-ban and ban duration live, no restart needed. LogFort re-applies these values automatically if fail2ban restarts.

### Notifications

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_NOTIFY_WEBHOOK_URL` | _(empty)_ | Generic webhook (POST JSON) |
| `LOGFORT_NOTIFY_TELEGRAM_TOKEN` / `_CHAT_ID` | _(empty)_ | Telegram bot |
| `LOGFORT_NOTIFY_DISCORD_URL` | _(empty)_ | Discord webhook |
| `LOGFORT_NOTIFY_RULES` | _(empty)_ | Comma-separated: `accepted_login`, `ban`, `new_country`, `threshold:N/dur` |

Env vars always override values saved via the UI.

---

## HTTP API

| Endpoint | Description |
|---|---|
| `GET /api/health` | Status, version, uptime, parse counters (never requires auth) |
| `GET /api/stats?window=24h` | Aggregates + timeline (`1h\|6h\|24h\|7d\|30d\|all`) |
| `GET /api/events` | Filterable event list (`type`, `ip`, `country`, `since`, `until`, `limit`, `offset`) |
| `GET /api/events.csv` | Same filters, CSV download (up to 10 000 rows) |
| `GET /api/bans?active=true` | Ban history |
| `GET /api/map?window=24h` | Geo-aggregated attack points |
| `GET /api/stream` | Live events via Server-Sent Events |
| `GET /metrics` | Prometheus text format (respects basic auth) |
| `POST /api/ban` / `POST /api/unban` | Manual banning (requires responder) |

---

## Supported Log Sources

| Source | Auto-detected by |
|---|---|
| sshd (`auth.log`, `secure`, OpenSSH 9+ `sshd-session`) | syslog/RFC3339 prefix + `proc=sshd` |
| nginx `error.log` | `YYYY/MM/DD HH:MM:SS [` prefix |
| nginx `access.log` | `IP - user [ts]` format, 401 responses only |
| fail2ban | `YYYY-MM-DD HH:MM:SS,ms fail2ban` prefix |
| systemd journal | `LOGFORT_BACKEND=journald` |

**Typical auth log paths:**

| Distro | Path |
|---|---|
| Debian / Ubuntu | `/var/log/auth.log` |
| RHEL / Fedora / CentOS | `/var/log/secure` |
| Arch / Alpine / Debian 13 | journald (`LOGFORT_BACKEND=journald`) |

---

## journald Backend

For systems that log to systemd journal instead of a file (Arch, Alpine, Debian 13+):

```yaml
services:
  logfort:
    image: ghcr.io/unwinds/logfort:latest
    group_add:
      - "NNN"   # systemd-journal GID: getent group systemd-journal | cut -d: -f3
    volumes:
      - /run/log/journal:/run/log/journal:ro
      - /var/log/journal:/var/log/journal:ro
      - /run/systemd/journal:/run/systemd/journal:ro
      - /etc/machine-id:/etc/machine-id:ro
      - ./data:/data
    environment:
      - LOGFORT_LISTEN=0.0.0.0:8080
      - LOGFORT_BACKEND=journald
      - LOGFORT_JOURNALD_UNIT=ssh.service
```

The install script generates this automatically when you choose the journald backend.

---

## Security Notes

- LogFort **binds to `127.0.0.1` by default** — do not expose it directly to the internet.
- The dashboard shows sensitive data (attacker IPs, login usernames, timing).
- Use an SSH tunnel, Tailscale, or WireGuard for remote access.
- Enable HTTP Basic Auth as an additional layer.
- The active banning feature modifies your firewall — review `LOGFORT_IGNORE_IPS` to avoid accidentally blocking legitimate IPs.

---

## Development

Requires Go 1.25+. No CGO — uses `modernc.org/sqlite` (pure Go SQLite).

```bash
# Build
go build -ldflags="-X main.version=dev" -o ./logfort ./cmd/logfort

# Tests (always with -race)
go test -race ./...

# Run locally against test fixture
LOGFORT_LOG_PATHS=$(pwd)/testdata/auth_debian.log \
LOGFORT_DB_PATH=/tmp/logfort-dev.db \
LOGFORT_LISTEN=127.0.0.1:8080 \
go run ./cmd/logfort

# Lint
golangci-lint run
```

---

## Releasing

```bash
git tag v1.2.3 && git push origin v1.2.3
```

Pushing a `v*` tag triggers GitHub Actions: tests → goreleaser → multi-arch Docker images (`linux/amd64`, `arm64`, `armv7`) pushed to `ghcr.io/unwinds/logfort`.

---

## License

[MIT](LICENSE)
