# LogFort

> Self-hosted dashboard for monitoring SSH and web authentication attacks in real time.

[![CI](https://github.com/unwinds/logfort/actions/workflows/ci.yml/badge.svg)](https://github.com/unwinds/logfort/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- **Live event feed** — failed and accepted logins stream in real time via SSE
- **Statistics** — top attacker IPs, usernames, countries, hourly/daily timeline
- **Attack map** — geo-located markers on an offline Leaflet map (no external tile servers)
- **Ban list** — view active and expired bans; one-click ban/unban from the UI
- **Active banning** — optional nftables or fail2ban integration
- **Notifications** — Telegram, Discord, or generic webhook; configurable rules (per-event or threshold-based)
- **Settings UI** — change notification config at runtime without restarting
- **nginx support** — parses nginx `error.log` (auth failures) and `access.log` (401 responses)
- **fail2ban log** — optional second source for ban/unban events
- **journald backend** — follow systemd journal instead of a log file
- **HTTP Basic Auth** — optional, protects all routes except `/api/health`
- **Privacy-first** — zero outbound requests; GeoIP is local `.mmdb`, map tiles are embedded GeoJSON

---

## Quick start

### Automated install (recommended)

The install script detects your distro, optionally installs fail2ban, asks whether to use `file` or `journald` backend, and writes a ready-to-run `docker-compose.yml`.

```bash
curl -fsSL https://raw.githubusercontent.com/unwinds/logfort/main/install.sh | sudo bash
```

Or with options:

```bash
sudo bash install.sh --dir /opt/logfort --image ghcr.io/unwinds/logfort:latest
```

Then:

```bash
cd /opt/logfort
docker compose up -d
# Open http://localhost:8080 (via SSH tunnel — see below)
```

### Manual Docker Compose

```yaml
# docker-compose.yml
services:
  logfort:
    image: ghcr.io/unwinds/logfort:latest
    container_name: logfort
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - /var/log/auth.log:/host/auth.log:ro
      - ./data:/data
    environment:
      - LOGFORT_LOG_PATHS=/host/auth.log
    restart: unless-stopped
```

```bash
docker compose up -d
```

### Access via SSH tunnel

LogFort binds to `127.0.0.1` by default. To reach it from your local machine:

```bash
ssh -L 8080:localhost:8080 user@yourserver
# Open http://localhost:8080
```

---

## Configuration

All settings are environment variables. Notification settings can also be changed at runtime via the Settings page in the UI.

### Core

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_LISTEN` | `127.0.0.1:8080` | HTTP bind address |
| `LOGFORT_BACKEND` | `file` | Log backend: `file` or `journald` |
| `LOGFORT_LOG_PATHS` | `/host/auth.log` | Comma-separated log paths (sshd, nginx error.log, nginx access.log auto-detected) |
| `LOGFORT_JOURNALD_UNIT` | `ssh.service` | systemd unit to follow when `LOGFORT_BACKEND=journald` |
| `LOGFORT_FAIL2BAN_LOG` | *(empty)* | Optional fail2ban log path, parsed as an extra source |
| `LOGFORT_DB_PATH` | `/data/logfort.db` | SQLite database path |
| `LOGFORT_GEOIP_DB` | `/data/geo.mmdb` | GeoIP mmdb path; silently skipped if missing |
| `LOGFORT_RETENTION_DAYS` | `90` | Purge events older than N days |
| `LOGFORT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOGFORT_HOME_LAT` / `_LON` | *(empty)* | Optional home-marker coordinates on the attack map |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_AUTH_ENABLED` | `false` | Enable HTTP Basic Auth on all routes except `/api/health` |
| `LOGFORT_AUTH_USER` | *(empty)* | Basic auth username (required when auth is enabled) |
| `LOGFORT_AUTH_PASS` | *(empty)* | Basic auth password (required when auth is enabled) |

### Active banning

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_RESPONDER_ENABLED` | `false` | Enable firewall integration |
| `LOGFORT_RESPONDER_BACKEND` | `nftables` | `nftables` or `fail2ban` |
| `LOGFORT_NFT_TABLE` | `inet filter` | nftables table (`family name`) |
| `LOGFORT_NFT_SET` | `logfort_block` | nftables set name |
| `LOGFORT_FAIL2BAN_JAIL` | `sshd` | fail2ban jail name |
| `LOGFORT_IGNORE_IPS` | RFC-1918 + loopback | Comma-separated CIDRs/IPs never banned |

### Notifications

| Variable | Default | Description |
|---|---|---|
| `LOGFORT_NOTIFY_WEBHOOK_URL` | *(empty)* | Generic webhook (POST JSON) |
| `LOGFORT_NOTIFY_TELEGRAM_TOKEN` | *(empty)* | Telegram bot token |
| `LOGFORT_NOTIFY_TELEGRAM_CHAT_ID` | *(empty)* | Telegram chat ID |
| `LOGFORT_NOTIFY_DISCORD_URL` | *(empty)* | Discord webhook URL |
| `LOGFORT_NOTIFY_RULES` | *(empty)* | Comma-separated trigger rules (see below) |

Env vars always take priority over values saved via the UI.

**Notification rules:**

| Rule | Fires when |
|---|---|
| `accepted_login` | A successful SSH login is detected |
| `ban` | An IP is banned |
| `new_country` | An attack arrives from a country not seen since startup |
| `threshold:N/dur` | An IP exceeds N events in the given window (e.g. `threshold:100/1h`) |

---

## Supported log sources

| Source | Auto-detected by |
|---|---|
| sshd (`auth.log`, `secure`) | `sshd[` prefix |
| nginx `error.log` | `YYYY/MM/DD HH:MM:SS [` prefix |
| nginx `access.log` | `IP - user [ts]` format, 401 responses only |
| fail2ban | `YYYY-MM-DD HH:MM:SS,ms fail2ban` prefix |
| systemd journal | `LOGFORT_BACKEND=journald` |

**Typical log paths by distro:**

| Distro | Path |
|---|---|
| Debian / Ubuntu | `/var/log/auth.log` |
| RHEL / Fedora / CentOS | `/var/log/secure` |
| Arch / Alpine | journald (`LOGFORT_BACKEND=journald`) |

---

## GeoIP (optional)

LogFort supports [DB-IP Lite](https://db-ip.com/db/lite.php.html) (free, CC-BY 4.0) and MaxMind GeoLite2 — both use the same mmdb binary format.

```bash
# Download DB-IP Lite (no account required)
curl -L "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz" \
  | gunzip > data/geo.mmdb
```

Place the file at `LOGFORT_GEOIP_DB` (default `/data/geo.mmdb`) and restart the container. If no file is found, the app works without geo data.

---

## journald backend

For systems that log to systemd journal instead of files:

```yaml
services:
  logfort:
    image: ghcr.io/unwinds/logfort:latest
    group_add:
      - "systemd-journal-gid"   # replace with output of: getent group systemd-journal | cut -d: -f3
    volumes:
      - /run/log/journal:/run/log/journal:ro
      - /var/log/journal:/var/log/journal:ro
      - /run/systemd/journal:/run/systemd/journal:ro
      - /etc/machine-id:/etc/machine-id:ro
      - ./data:/data
    environment:
      - LOGFORT_BACKEND=journald
      - LOGFORT_JOURNALD_UNIT=ssh.service
```

The install script generates this automatically when you choose the journald backend.

---

## Security notice

- LogFort **listens on `127.0.0.1` by default** — do not expose it directly to the internet.
- The dashboard shows sensitive data (attacker IPs, login activity).
- Use an SSH tunnel, Tailscale, or WireGuard for remote access.
- Enable HTTP Basic Auth (`LOGFORT_AUTH_ENABLED=true`) as an additional layer.
- The active banning feature modifies your firewall. Enable it only intentionally — review `LOGFORT_IGNORE_IPS` before use.

---

## Comparison

| | LogFort | Grafana + Loki + Prometheus |
|---|---|---|
| Containers | **1** | 4–6 |
| Setup | **`install.sh`** | Manual config |
| GeoIP | **Local mmdb** | External or self-hosted |
| Map tiles | **Embedded GeoJSON** | External tile server |
| Outbound requests | **None** | Prometheus, Grafana Cloud, etc. |
| Notifications | **Built-in** | Alertmanager |

---

## Privacy

LogFort makes **zero outbound network requests** with your data:

- GeoIP is resolved against a local `.mmdb` file
- The attack map uses embedded offline GeoJSON (no Leaflet CDN at runtime)
- No analytics, no telemetry, no CDN dependencies

The only outbound connections are **opt-in notifications** (Telegram / Discord / webhook), explicitly configured by you.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
