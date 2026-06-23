#!/usr/bin/env bash
# logfort installer — sets up Docker Compose stack on a Linux host.
# Usage: curl -fsSL https://raw.githubusercontent.com/unwinds/logfort/main/install.sh | bash
#   or: bash install.sh [--dir /opt/logfort] [--image ghcr.io/unwinds/logfort:latest]
set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
LOGFORT_IMAGE="${LOGFORT_IMAGE:-ghcr.io/unwinds/logfort:latest}"
INSTALL_DIR="${LOGFORT_DIR:-/opt/logfort}"

# ── helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[logfort]${NC} $*"; }
warn()  { echo -e "${YELLOW}[logfort]${NC} $*"; }
error() { echo -e "${RED}[logfort]${NC} $*" >&2; exit 1; }
ask()   { echo -e "${BOLD}$*${NC}"; }

# ── arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)   INSTALL_DIR="$2"; shift 2 ;;
    --image) LOGFORT_IMAGE="$2"; shift 2 ;;
    *) error "unknown option: $1" ;;
  esac
done

# ── root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "run as root (sudo bash install.sh)"
fi

# ── detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID_LIKE:-$ID}"
  else
    echo "unknown"
  fi
}

DISTRO_LIKE=$(detect_distro)
PKG_MGR=""
if echo "$DISTRO_LIKE" | grep -qiE "debian|ubuntu"; then
  PKG_MGR="apt"
elif echo "$DISTRO_LIKE" | grep -qiE "rhel|fedora|centos|rocky|alma"; then
  if command -v dnf &>/dev/null; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
else
  warn "unknown distro family '$DISTRO_LIKE' — skipping package installs"
fi

install_pkg() {
  local pkg="$1"
  info "installing $pkg…"
  case "$PKG_MGR" in
    apt) apt-get install -y -q "$pkg" ;;
    dnf) dnf install -y "$pkg" ;;
    yum) yum install -y "$pkg" ;;
    *)   warn "cannot install $pkg automatically; please install it manually" ;;
  esac
}

# ── docker ────────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  warn "Docker is not installed."
  ask "Install Docker automatically? [y/N]"
  read -r ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    info "installing Docker via get.docker.com…"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
  else
    error "Docker is required. Install it first: https://docs.docker.com/engine/install/"
  fi
fi

# ── fail2ban (optional) ───────────────────────────────────────────────────────
FAIL2BAN_LOG=""
FAIL2BAN_JUST_INSTALLED=false
if ! command -v fail2ban-client &>/dev/null; then
  ask "fail2ban is not installed. Install it now? [y/N]"
  read -r ans
  if [[ "$ans" =~ ^[Yy]$ ]] && [[ -n "$PKG_MGR" ]]; then
    install_pkg fail2ban
    systemctl enable --now fail2ban || true
    FAIL2BAN_JUST_INSTALLED=true
  fi
fi
if command -v fail2ban-client &>/dev/null; then
  if $FAIL2BAN_JUST_INSTALLED || [[ -f /var/log/fail2ban.log ]]; then
    FAIL2BAN_LOG="/var/log/fail2ban.log"
    info "fail2ban log: $FAIL2BAN_LOG"
  fi
fi

# ── backend selection ─────────────────────────────────────────────────────────
BACKEND="file"
JOURNALD_UNIT="ssh.service"

# Auto-suggest journald when no auth log file is present.
HAS_AUTH_LOG=false
for candidate in /var/log/auth.log /var/log/secure; do
  if [[ -r "$candidate" ]]; then HAS_AUTH_LOG=true; break; fi
done

if $HAS_AUTH_LOG; then
  DEFAULT_BACKEND="1"
else
  DEFAULT_BACKEND="2"
  info "no auth log file found — journald backend recommended."
fi

ask "Log backend: (1) file  (2) journald  [${DEFAULT_BACKEND}]:"
read -r backend_choice
[[ -z "$backend_choice" ]] && backend_choice="$DEFAULT_BACKEND"

if [[ "$backend_choice" == "2" ]]; then
  if ! command -v journalctl &>/dev/null; then
    error "journalctl not found — journald backend requires systemd on the host. Switch to file backend or install systemd."
  fi
  BACKEND="journald"
  ask "systemd unit to follow [ssh.service]:"
  read -r unit_input
  [[ -n "$unit_input" ]] && JOURNALD_UNIT="$unit_input"
  info "journald backend: unit=$JOURNALD_UNIT"
fi

# ── detect auth log path (file backend only) ──────────────────────────────────
AUTH_LOG=""
if [[ "$BACKEND" == "file" ]]; then
  for candidate in /var/log/auth.log /var/log/secure; do
    if [[ -r "$candidate" ]]; then
      AUTH_LOG="$candidate"
      break
    fi
  done

  if [[ -z "$AUTH_LOG" ]]; then
    warn "could not auto-detect auth log path."
    ask "Enter path to your auth/sshd log file:"
    read -r AUTH_LOG
    [[ -r "$AUTH_LOG" ]] || error "file not found or not readable: $AUTH_LOG"
  fi
  info "auth log: $AUTH_LOG"
fi

# ── optional home coordinates ─────────────────────────────────────────────────
HOME_LAT=""
HOME_LON=""
ask "Enter your server's latitude for the attack map (optional, press Enter to skip):"
read -r HOME_LAT
if [[ -n "$HOME_LAT" ]]; then
  ask "Enter longitude:"
  read -r HOME_LON
fi

# ── listen port ───────────────────────────────────────────────────────────────
LISTEN_PORT=8080
ask "Dashboard port [8080]:"
read -r input_port
[[ -n "$input_port" ]] && LISTEN_PORT="$input_port"

# ── prepare install dir ───────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/data"
info "install directory: $INSTALL_DIR"

# ── generate docker-compose.yml ───────────────────────────────────────────────
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# Build volumes and env blocks depending on backend.
if [[ "$BACKEND" == "journald" ]]; then
  # Mount host journal files and the systemd journal socket so that journalctl
  # inside the container can read and follow the host journal.
  # /run/log/journal — volatile (tmpfs) journal; /var/log/journal — persistent.
  # /run/systemd/journal — socket dir needed for --follow to get live events.
  # /etc/machine-id — required for journalctl to identify which journal to open.
  VOLUMES="      - /run/log/journal:/run/log/journal:ro"
  VOLUMES="${VOLUMES}"$'\n'"      - /var/log/journal:/var/log/journal:ro"
  VOLUMES="${VOLUMES}"$'\n'"      - /run/systemd/journal:/run/systemd/journal:ro"
  VOLUMES="${VOLUMES}"$'\n'"      - /etc/machine-id:/etc/machine-id:ro"
  VOLUMES="${VOLUMES}"$'\n'"      - ./data:/data"

  # Detect the systemd-journal GID on this host so the container user can read
  # journal files (which are group-readable by systemd-journal).
  JOURNAL_GID=$(getent group systemd-journal 2>/dev/null | cut -d: -f3 || echo "")

  ENV_BLOCK="      - LOGFORT_BACKEND=journald"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_JOURNALD_UNIT=${JOURNALD_UNIT}"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_DB_PATH=/data/logfort.db"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_GEOIP_DB=/data/geo.mmdb"
else
  VOLUMES="      - ${AUTH_LOG}:/host/auth.log:ro"
  LOG_PATHS="/host/auth.log"
  if [[ -n "$FAIL2BAN_LOG" ]]; then
    VOLUMES="${VOLUMES}"$'\n'"      - ${FAIL2BAN_LOG}:/host/fail2ban.log:ro"
  fi
  VOLUMES="${VOLUMES}"$'\n'"      - ./data:/data"

  ENV_BLOCK="      - LOGFORT_LOG_PATHS=${LOG_PATHS}"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_DB_PATH=/data/logfort.db"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_GEOIP_DB=/data/geo.mmdb"
  if [[ -n "$FAIL2BAN_LOG" ]]; then
    ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_FAIL2BAN_LOG=/host/fail2ban.log"
  fi
fi

if [[ -n "$HOME_LAT" ]] && [[ -n "$HOME_LON" ]]; then
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_HOME_LAT=${HOME_LAT}"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_HOME_LON=${HOME_LON}"
fi

# Build optional group_add block for journald GID.
GROUP_ADD_BLOCK=""
if [[ "$BACKEND" == "journald" ]] && [[ -n "${JOURNAL_GID:-}" ]]; then
  GROUP_ADD_BLOCK=$'    group_add:\n'"      - \"${JOURNAL_GID}\""
fi

{
  echo "# Generated by logfort install.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "services:"
  echo "  logfort:"
  echo "    image: ${LOGFORT_IMAGE}"
  echo "    container_name: logfort"
  echo "    restart: unless-stopped"
  echo "    ports:"
  echo "      - \"127.0.0.1:${LISTEN_PORT}:8080\""
  echo "    volumes:"
  echo "${VOLUMES}"
  if [[ -n "$GROUP_ADD_BLOCK" ]]; then
    echo "$GROUP_ADD_BLOCK"
  fi
  echo "    environment:"
  echo "${ENV_BLOCK}"
} > "$COMPOSE_FILE"

info "docker-compose.yml written to $COMPOSE_FILE"

# ── GeoIP hint ────────────────────────────────────────────────────────────────
YEAR_MONTH=$(date +%Y-%m)
info ""
info "Optional: download a free GeoIP database for the attack map:"
info "  curl -L \"https://download.db-ip.com/free/dbip-city-lite-${YEAR_MONTH}.mmdb.gz\" | gunzip > ${INSTALL_DIR}/data/geo.mmdb"
info ""

# ── start ─────────────────────────────────────────────────────────────────────
ask "Start logfort now? [Y/n]"
read -r ans
if [[ ! "$ans" =~ ^[Nn]$ ]]; then
  docker compose -f "$COMPOSE_FILE" pull
  docker compose -f "$COMPOSE_FILE" up -d
  info "logfort is running on http://127.0.0.1:${LISTEN_PORT}"
  info "Tip: access via SSH tunnel: ssh -L ${LISTEN_PORT}:127.0.0.1:${LISTEN_PORT} user@yourserver"
else
  info "Start later with: docker compose -f $COMPOSE_FILE up -d"
fi
