# SSHWatch

> Лёгкий self-hosted дашборд для мониторинга SSH-атак в реальном времени.  
> Lightweight self-hosted dashboard to visualise SSH brute-force attacks in real time.

<!-- TODO: add hero GIF / screenshot after map is implemented (v0.4) -->

[![CI](https://github.com/unwinds/sshwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/unwinds/sshwatch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

SSHWatch reads your server's authentication log, parses every login attempt, and serves a live dashboard with:

- **Event feed** — every failed/accepted login in real time
- **Statistics** — top attacker IPs, usernames, countries, timeline
- **Attack map** — geo-located markers on an offline map *(v0.4)*
- **Ban list** — fail2ban activity *(v0.5)*
- **Active banning** — optional, opt-in *(v0.6)*

**Privacy-first.** No external tile servers, no cloud GeoIP lookups, no telemetry. Everything runs in one container.

---

## Quick start

### Docker Compose (recommended)

```yaml
# docker-compose.yml
services:
  sshwatch:
    image: ghcr.io/sshwatch/sshwatch:latest
    container_name: sshwatch
    ports:
      - "127.0.0.1:8080:8080"   # localhost only
    volumes:
      - /var/log/auth.log:/host/auth.log:ro
      - ./data:/data
    environment:
      - SSHWATCH_LOG_PATHS=/host/auth.log
    restart: unless-stopped
```

```bash
docker compose up -d
# Open http://localhost:8080 (via SSH tunnel if needed)
```

### Docker run

```bash
docker run -d \
  -p 127.0.0.1:8080:8080 \
  -v /var/log/auth.log:/host/auth.log:ro \
  -v $(pwd)/data:/data \
  -e SSHWATCH_LOG_PATHS=/host/auth.log \
  ghcr.io/sshwatch/sshwatch:latest
```

### Access over SSH tunnel

SSHWatch binds to `127.0.0.1` by default. To reach it from your machine:

```bash
ssh -L 8080:localhost:8080 user@yourserver
# then open http://localhost:8080
```

---

## ⚠️ Security notice

- SSHWatch **listens on `127.0.0.1` by default**. Do **not** expose it directly to the internet without authentication (v1.0).
- The dashboard shows sensitive data (attacker IPs, your SSH activity).
- Use an SSH tunnel or VPN (Tailscale / WireGuard) for remote access.
- The active ban feature (`SSHWATCH_RESPONDER_ENABLED=true`) modifies your firewall. Enable it only intentionally.

---

## Configuration

All settings are via environment variables.

| Variable | Default | Description |
|---|---|---|
| `SSHWATCH_LISTEN` | `127.0.0.1:8080` | Bind address. **Keep localhost.** |
| `SSHWATCH_BACKEND` | `file` | Log backend: `file` or `journald` |
| `SSHWATCH_LOG_PATHS` | `/host/auth.log` | Comma-separated log file paths |
| `SSHWATCH_FAIL2BAN_LOG` | *(empty)* | Path to fail2ban.log (optional) |
| `SSHWATCH_DB_PATH` | `/data/sshwatch.db` | SQLite database file |
| `SSHWATCH_GEOIP_DB` | `/data/geo.mmdb` | GeoIP mmdb file (optional, see below) |
| `SSHWATCH_RETENTION_DAYS` | `90` | Delete events older than N days |
| `SSHWATCH_HOME_LAT` / `_LON` | *(empty)* | Your server location for arc rendering |
| `SSHWATCH_RESPONDER_ENABLED` | `false` | Enable active banning (opt-in) |
| `SSHWATCH_LOG_LEVEL` | `info` | `debug\|info\|warn\|error` |

### Supported log formats

| Distro | Default log path |
|---|---|
| Debian / Ubuntu | `/var/log/auth.log` |
| RHEL / Fedora / CentOS | `/var/log/secure` |
| Arch / Alpine | `/var/log/auth.log` or journald |

Mount the appropriate path as `/host/auth.log:ro`.

### GeoIP database (optional)

SSHWatch uses the [DB-IP Lite](https://db-ip.com/db/lite.php.html) (free, CC-BY) or MaxMind GeoLite2 format.

```bash
# DB-IP Lite (no account required):
wget -O data/geo.mmdb.gz https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz
gunzip data/geo.mmdb.gz
```

If no database is found, SSHWatch works without geo data (map shows "unknown").

---

## Comparison

| | SSHWatch | Grafana + Prometheus + Loki |
|---|---|---|
| Containers | **1** | 4–6 |
| Setup time | **30 seconds** | 30–60 minutes |
| GeoIP | **Local, private** | External or self-hosted |
| Map tiles | **Offline GeoJSON** | External tile server |
| External calls | **None** | Prometheus, Grafana Cloud, etc. |
| Disk (base) | ~20 MB | 500 MB+ |

---

## Privacy

SSHWatch makes **zero outbound network requests** with your data:
- GeoIP lookups are done against a local `.mmdb` file
- The attack map uses an embedded offline GeoJSON
- No analytics, no telemetry, no CDN

The only outbound connections are opt-in notifications (Telegram/Discord/webhook), enabled explicitly via environment variables.

---

## Roadmap

| Version | Feature |
|---|---|
| v0.1 ✅ | Log parsing, SQLite storage, REST API, basic dashboard |
| v0.2 | GeoIP enrichment, top-N stats, timeline chart |
| v0.3 | SSE real-time event feed |
| v0.4 | Attack map (Leaflet + offline GeoJSON) |
| v0.5 | fail2ban log integration, ban list |
| v0.6 | Active banning (nftables / fail2ban-client) |
| v0.7 | Notifications (webhook / Telegram / Discord) |
| v1.0 | Auth, multi-arch release, goreleaser |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
