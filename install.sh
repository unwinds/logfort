#!/usr/bin/env bash
# logfort installer — sets up LogFort on a Linux host (Docker Compose or
# a bare-metal binary with a systemd unit).
# Usage: curl -fsSL https://raw.githubusercontent.com/unwinds/logfort/main/install.sh | bash
#   or: bash install.sh [--dir /opt/logfort] [--image ghcr.io/unwinds/logfort:latest]
#   or: bash install.sh --uninstall
set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
LOGFORT_IMAGE="${LOGFORT_IMAGE:-ghcr.io/unwinds/logfort:latest}"
INSTALL_DIR="${LOGFORT_DIR:-/opt/logfort}"
UNINSTALL=false
SYSTEMD_UNIT_FILE="/etc/systemd/system/logfort.service"
BIN_PATH="/usr/local/bin/logfort"
F2B_DROPIN="/etc/fail2ban/jail.d/logfort.local"
F2B_FILTER="/etc/fail2ban/filter.d/logfort-sshd.conf"

# ── helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[logfort]${NC} $*"; }
warn()  { echo -e "${YELLOW}[logfort]${NC} $*"; }
error() { echo -e "${RED}[logfort]${NC} $*" >&2; exit 1; }
ask()   { echo -e "${BOLD}$*${NC}"; }

# read_tty — reads one line from /dev/tty so prompts work via curl | bash.
read_tty() { read -r "$1" </dev/tty; }

# ── arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)       INSTALL_DIR="$2"; shift 2 ;;
    --image)     LOGFORT_IMAGE="$2"; shift 2 ;;
    --uninstall) UNINSTALL=true; shift ;;
    *) error "unknown option: $1" ;;
  esac
done

# ── root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "run as root (sudo bash install.sh)"
fi

# ── uninstall ─────────────────────────────────────────────────────────────────
if $UNINSTALL; then
  info "uninstalling LogFort…"
  # Docker install
  if [[ -f "$INSTALL_DIR/docker-compose.yml" ]] && command -v docker &>/dev/null; then
    docker compose -f "$INSTALL_DIR/docker-compose.yml" down 2>/dev/null || true
    info "stopped and removed the container."
  fi
  # Bare-metal install
  if [[ -f "$SYSTEMD_UNIT_FILE" ]]; then
    systemctl disable --now logfort 2>/dev/null || true
    rm -f "$SYSTEMD_UNIT_FILE"
    systemctl daemon-reload 2>/dev/null || true
    info "removed the systemd unit."
  fi
  [[ -f "$BIN_PATH" ]] && rm -f "$BIN_PATH" && info "removed $BIN_PATH."
  # fail2ban drop-ins written by this script (they keep protecting SSH on
  # their own, so leaving them in place is a safe default)
  if [[ -f "$F2B_DROPIN" || -f "$F2B_FILTER" ]]; then
    ask "Remove the fail2ban sshd jail tuning installed by LogFort (restores stock filter)? [y/N]"
    read_tty ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      rm -f "$F2B_DROPIN" "$F2B_FILTER"
      systemctl restart fail2ban 2>/dev/null || service fail2ban restart 2>/dev/null || true
      info "fail2ban jail files removed, fail2ban restarted."
    fi
  fi
  if [[ -d "$INSTALL_DIR" ]]; then
    ask "Delete ${INSTALL_DIR} including the events database and GeoIP files? [y/N]"
    read_tty ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      rm -rf "$INSTALL_DIR"
      info "removed $INSTALL_DIR."
    else
      rm -f "$INSTALL_DIR/docker-compose.yml" "$INSTALL_DIR/logfort.env"
      info "kept $INSTALL_DIR (database and GeoIP data) — delete manually when ready."
    fi
  fi
  info "LogFort uninstalled."
  exit 0
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

# ── install method ────────────────────────────────────────────────────────────
# Docker keeps the host clean; bare-metal suits hosts without Docker or users
# who prefer not to hand a container the fail2ban socket / log access.
INSTALL_MODE="docker"
ask "Install method: (1) Docker container (recommended)  (2) bare-metal binary + systemd  [1]:"
read_tty mode_choice
if [[ "$mode_choice" == "2" ]]; then
  INSTALL_MODE="systemd"
  command -v systemctl &>/dev/null || error "bare-metal install requires systemd. Use the Docker method instead."
  info "bare-metal install: binary at ${BIN_PATH}, systemd unit logfort.service"
fi

# ── docker ────────────────────────────────────────────────────────────────────
if [[ "$INSTALL_MODE" == "docker" ]] && ! command -v docker &>/dev/null; then
  warn "Docker is not installed."
  ask "Install Docker automatically? [Y/n]"
  read_tty ans
  if [[ ! "$ans" =~ ^[Nn]$ ]]; then
    info "installing Docker via get.docker.com…"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
  else
    error "Docker is required. Install it first (https://docs.docker.com/engine/install/) or re-run and pick the bare-metal method."
  fi
fi

# ── fail2ban (optional) ───────────────────────────────────────────────────────
FAIL2BAN_LOG=""
if ! command -v fail2ban-client &>/dev/null; then
  ask "fail2ban is not installed. Install it now? [Y/n]"
  read_tty ans
  if [[ ! "$ans" =~ ^[Nn]$ ]] && [[ -n "$PKG_MGR" ]]; then
    install_pkg fail2ban
    systemctl enable --now fail2ban || true
  fi
fi
if command -v fail2ban-client &>/dev/null; then
  if [[ -f /var/log/fail2ban.log ]]; then
    FAIL2BAN_LOG="/var/log/fail2ban.log"
    info "fail2ban log: $FAIL2BAN_LOG"
  else
    warn "fail2ban log not found at /var/log/fail2ban.log — fail2ban may be logging via journald on this system. Skipping fail2ban log ingestion."
  fi
fi

# ── fail2ban sshd jail tuning ─────────────────────────────────────────────────
# The stock sshd filter matches auxiliary log lines too ("Invalid user X",
# pam_unix failures) — for an unknown username every wrong password produces
# TWO or more matches, so maxretry=3 bans after just 2 real attempts. The
# logfort-sshd filter below counts only "Failed password/keyboard-interactive"
# lines: exactly one per wrong password, so maxretry means what it says.
F2B_MAXRETRY=3
F2B_BANHOURS=1
if command -v fail2ban-client &>/dev/null; then
  [[ -f "$F2B_DROPIN" ]] && info "existing logfort fail2ban drop-in found — it will be updated."
  ask "Configure the fail2ban sshd jail (exact attempt counting; recommended)? [Y/n]"
  read_tty ans
  if [[ ! "$ans" =~ ^[Nn]$ ]]; then
    ask "Failed password attempts before ban [${F2B_MAXRETRY}]:"
    read_tty v
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 99 )); then F2B_MAXRETRY="$v";
    elif [[ -n "$v" ]]; then warn "invalid value '$v' — keeping ${F2B_MAXRETRY}"; fi
    ask "Ban duration in hours [${F2B_BANHOURS}]:"
    read_tty v
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 720 )); then F2B_BANHOURS="$v";
    elif [[ -n "$v" ]]; then warn "invalid value '$v' — keeping ${F2B_BANHOURS}"; fi

    mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
    cat > "$F2B_FILTER" <<'F2BFILTER'
# Managed by logfort install.sh — safe to edit or delete.
# Counts ONLY actual failed authentication attempts: sshd logs exactly one
# "Failed password" / "Failed keyboard-interactive" line per wrong password.
# The stock sshd filter additionally matches "Invalid user …" and pam_unix
# lines, which double-counts attempts against unknown usernames and makes
# bans fire earlier than maxretry suggests.
[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd(?:-session)?

failregex = ^%(__prefix_line)sFailed (?:password|keyboard-interactive(?:/pam)?) for (?:invalid user )?.* from <HOST>( port \d+)?( ssh\d*)?\s*$

ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=sshd.service + _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session
F2BFILTER

    cat > "$F2B_DROPIN" <<F2BJAIL
# Managed by logfort install.sh — safe to edit or delete.
# Uses the logfort-sshd filter so maxretry counts real password attempts.
[sshd]
enabled  = true
filter   = logfort-sshd
maxretry = ${F2B_MAXRETRY}
findtime = 10m
bantime  = ${F2B_BANHOURS}h
F2BJAIL

    systemctl restart fail2ban 2>/dev/null || service fail2ban restart 2>/dev/null || true
    sleep 2
    # Verify the settings actually took effect — a config typo would leave
    # fail2ban dead and the host unprotected.
    if fail2ban-client ping &>/dev/null; then
      EFF_RETRY=$(fail2ban-client get sshd maxretry 2>/dev/null | tr -d '[:space:]' || echo "?")
      EFF_BAN=$(fail2ban-client get sshd bantime 2>/dev/null | tr -d '[:space:]' || echo "?")
      if [[ "$EFF_RETRY" == "$F2B_MAXRETRY" ]]; then
        info "fail2ban sshd jail verified: ${EFF_RETRY} attempts / 10 min window / ${EFF_BAN}s ban"
      else
        warn "fail2ban is running but sshd jail reports maxretry=${EFF_RETRY} (expected ${F2B_MAXRETRY}) — check: fail2ban-client status sshd"
      fi
    else
      warn "fail2ban did not come back up after restart! Check: journalctl -u fail2ban -n 30"
    fi
  fi
fi

# ── fail2ban control from the web UI ──────────────────────────────────────────
# Mounting fail2ban's command socket lets LogFort ban/unban IPs and edit the
# jail's maxretry/bantime from the Settings → Firewall tab. The socket is
# root-only, so the container must run as root when this is enabled.
F2B_CONTROL=false
if command -v fail2ban-client &>/dev/null; then
  ask "Manage fail2ban from the LogFort web UI (ban/unban IPs, change attempts/ban duration)? [Y/n]"
  read_tty ans
  if [[ ! "$ans" =~ ^[Nn]$ ]]; then
    F2B_CONTROL=true
    if [[ "$INSTALL_MODE" == "docker" ]]; then
      info "web UI fail2ban control enabled (container will run as root to reach /var/run/fail2ban)"
    else
      info "web UI fail2ban control enabled (the service runs as root and talks to the fail2ban socket directly)"
    fi
  fi
fi

# ── backend selection ─────────────────────────────────────────────────────────
BACKEND="file"

# Auto-detect the sshd systemd unit: Debian/Ubuntu name the real unit
# "ssh.service" (with "sshd.service" frequently present only as an alias),
# Fedora/RHEL/CentOS name it "sshd.service". Following the wrong unit makes
# `journalctl --unit=…` return nothing *silently* (no error), so the dashboard
# stays empty with no clue why. Check ssh.service FIRST so Debian/Ubuntu latch
# onto their real unit instead of the sshd.service alias (which journalctl
# inside the container cannot resolve back to ssh.service).
JOURNALD_UNIT="ssh.service"
if command -v systemctl &>/dev/null; then
  if systemctl list-unit-files 2>/dev/null | grep -Eq '^ssh\.service'; then
    JOURNALD_UNIT="ssh.service"
  elif systemctl list-unit-files 2>/dev/null | grep -Eq '^sshd\.service'; then
    JOURNALD_UNIT="sshd.service"
  fi
fi

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
read_tty backend_choice
[[ -z "$backend_choice" ]] && backend_choice="$DEFAULT_BACKEND"

if [[ "$backend_choice" == "2" ]]; then
  if ! command -v journalctl &>/dev/null; then
    error "journalctl not found — journald backend requires systemd on the host. Switch to file backend or install systemd."
  fi
  BACKEND="journald"
  ask "systemd unit to follow [${JOURNALD_UNIT}]:"
  read_tty unit_input
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
    read_tty AUTH_LOG
    [[ -r "$AUTH_LOG" ]] || error "file not found or not readable: $AUTH_LOG"
  fi
  info "auth log: $AUTH_LOG"
fi

# ── container access to log files ─────────────────────────────────────────────
# /var/log is mounted as a DIRECTORY, not per-file: bind-mounting a single
# file pins its inode, so after the first logrotate the container keeps
# reading the rotated (frozen) file and the dashboard silently goes quiet.
#
# The container runs as a non-root user, while auth.log is typically
# 640 root:adm (Ubuntu: syslog:adm) — without extra groups the container gets
# "permission denied" and, again, a silently empty dashboard. group_add with
# the log's group fixes Debian/Ubuntu; RHEL's /var/log/secure is 600 root:root
# and needs the root fallback.
RUN_AS_ROOT=false
GROUP_ADD_GIDS=()
$F2B_CONTROL && RUN_AS_ROOT=true

add_log_group() {
  local file="$1" perm gid
  [[ -f "$file" ]] || return 0
  perm=$(stat -c %a "$file" 2>/dev/null) || return 0
  gid=$(stat -c %g "$file" 2>/dev/null) || return 0
  # group-read bit = second-to-last octal digit >= 4
  if [[ "${perm:${#perm}-2:1}" -ge 4 ]]; then
    local g
    for g in "${GROUP_ADD_GIDS[@]:-}"; do [[ "$g" == "$gid" ]] && return 0; done
    GROUP_ADD_GIDS+=("$gid")
  else
    warn "$file is not group-readable (mode $perm) — the container will run as root to read it."
    RUN_AS_ROOT=true
  fi
}

if [[ "$INSTALL_MODE" == "docker" ]]; then
  if ! $RUN_AS_ROOT; then
    [[ "$BACKEND" == "file" ]] && add_log_group "$AUTH_LOG"
    [[ -n "$FAIL2BAN_LOG" ]] && add_log_group "$FAIL2BAN_LOG"
  fi

  if [[ "$BACKEND" == "journald" ]] && ! $RUN_AS_ROOT; then
    JOURNAL_GID=$(getent group systemd-journal 2>/dev/null | cut -d: -f3 || echo "")
    [[ -n "$JOURNAL_GID" ]] && GROUP_ADD_GIDS+=("$JOURNAL_GID")
  fi
fi

# ── optional home coordinates ─────────────────────────────────────────────────
HOME_LAT=""
HOME_LON=""
ask "Enter your server's latitude for the attack map (optional, press Enter to skip):"
read_tty HOME_LAT
if [[ -n "$HOME_LAT" ]]; then
  ask "Enter longitude:"
  read_tty HOME_LON
fi

# ── listen port ───────────────────────────────────────────────────────────────
LISTEN_PORT=8080
ask "Dashboard port [8080]:"
read_tty input_port
if [[ -n "$input_port" ]]; then
  if [[ "$input_port" =~ ^[0-9]+$ ]] && (( input_port >= 1 && input_port <= 65535 )); then
    LISTEN_PORT="$input_port"
  else
    warn "invalid port '$input_port' — keeping 8080"
  fi
fi

# ── prepare install dir ───────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/data"
if [[ "$INSTALL_MODE" == "docker" ]]; then
  # The non-root container user must be able to create the SQLite database.
  chmod 777 "$INSTALL_DIR/data"
fi
info "install directory: $INSTALL_DIR"

# ── generate docker-compose.yml ───────────────────────────────────────────────
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
if [[ "$INSTALL_MODE" == "docker" ]]; then

# container_log_path <path> → path of the file as seen inside the container.
container_log_path() {
  case "$1" in
    /var/log/*) echo "/host/log/${1#/var/log/}" ;;
    *)          echo "/host/$(basename "$1")" ;;
  esac
}

VAR_LOG_MOUNTED=false
[[ "$BACKEND" == "file" && "$AUTH_LOG" == /var/log/* ]] && VAR_LOG_MOUNTED=true
[[ -n "$FAIL2BAN_LOG" && "$FAIL2BAN_LOG" == /var/log/* ]] && VAR_LOG_MOUNTED=true

NL=$'\n'
VOLUMES=""
ENV_BLOCK="      - LOGFORT_LISTEN=0.0.0.0:8080"
ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_DB_PATH=/data/logfort.db"
ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_GEOIP_DB=/data/geo.mmdb"
ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_ASN_DB=/data/asn.mmdb"

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
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_BACKEND=journald"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_JOURNALD_UNIT=${JOURNALD_UNIT}"
else
  AUTH_LOG_IN_CONTAINER=$(container_log_path "$AUTH_LOG")
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_LOG_PATHS=${AUTH_LOG_IN_CONTAINER}"
fi

if [[ -n "$FAIL2BAN_LOG" ]]; then
  F2B_LOG_IN_CONTAINER=$(container_log_path "$FAIL2BAN_LOG")
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_FAIL2BAN_LOG=${F2B_LOG_IN_CONTAINER}"
fi

# One /var/log directory mount covers auth.log + fail2ban.log and survives
# logrotate; files outside /var/log are mounted individually (with a warning).
if $VAR_LOG_MOUNTED; then
  VOLUMES="${VOLUMES:+${VOLUMES}${NL}}      - /var/log:/host/log:ro"
fi
if [[ "$BACKEND" == "file" && "$AUTH_LOG" != /var/log/* ]]; then
  warn "auth log is outside /var/log — mounting the file directly. Log rotation will break ingestion until the container restarts."
  VOLUMES="${VOLUMES:+${VOLUMES}${NL}}      - ${AUTH_LOG}:${AUTH_LOG_IN_CONTAINER}:ro"
fi
if [[ -n "$FAIL2BAN_LOG" && "$FAIL2BAN_LOG" != /var/log/* ]]; then
  VOLUMES="${VOLUMES:+${VOLUMES}${NL}}      - ${FAIL2BAN_LOG}:${F2B_LOG_IN_CONTAINER}:ro"
fi

if $F2B_CONTROL; then
  VOLUMES="${VOLUMES:+${VOLUMES}${NL}}      - /var/run/fail2ban:/var/run/fail2ban"
  ENV_BLOCK="${ENV_BLOCK}${NL}      - LOGFORT_RESPONDER_ENABLED=true"
  ENV_BLOCK="${ENV_BLOCK}${NL}      - LOGFORT_RESPONDER_BACKEND=fail2ban"
  ENV_BLOCK="${ENV_BLOCK}${NL}      - LOGFORT_FAIL2BAN_JAIL=sshd"
fi

# Host timezone: sshd/fail2ban write zone-less local-time timestamps; the
# parser interprets them in the container's local zone, which must match.
VOLUMES="${VOLUMES:+${VOLUMES}${NL}}      - /etc/localtime:/etc/localtime:ro"
VOLUMES="${VOLUMES}${NL}      - ./data:/data"

if [[ -n "$HOME_LAT" ]] && [[ -n "$HOME_LON" ]]; then
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_HOME_LAT=${HOME_LAT}"
  ENV_BLOCK="${ENV_BLOCK}"$'\n'"      - LOGFORT_HOME_LON=${HOME_LON}"
fi

USER_LINE=""
GROUP_ADD_BLOCK=""
if $RUN_AS_ROOT; then
  USER_LINE='    user: "0:0"'
elif [[ ${#GROUP_ADD_GIDS[@]} -gt 0 ]]; then
  GROUP_ADD_BLOCK="    group_add:"
  for gid in "${GROUP_ADD_GIDS[@]}"; do
    GROUP_ADD_BLOCK="${GROUP_ADD_BLOCK}"$'\n'"      - \"${gid}\""
  done
fi

{
  echo "# Generated by logfort install.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "services:"
  echo "  logfort:"
  echo "    image: ${LOGFORT_IMAGE}"
  echo "    container_name: logfort"
  echo "    restart: unless-stopped"
  if [[ -n "$USER_LINE" ]]; then
    echo "$USER_LINE"
  fi
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

else
# ── bare-metal: download binary + write env file + systemd unit ───────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)   REL_ARCH="amd64" ;;
  aarch64|arm64)  REL_ARCH="arm64" ;;
  armv7l|armhf)   REL_ARCH="armv7" ;;
  *) error "unsupported architecture: $ARCH (releases cover x86_64, aarch64, armv7)" ;;
esac
TARBALL_URL="https://github.com/unwinds/logfort/releases/latest/download/logfort_linux_${REL_ARCH}.tar.gz"
info "downloading ${TARBALL_URL}…"
BIN_TMP=$(mktemp -d)
curl -fsSL "$TARBALL_URL" | tar -xz -C "$BIN_TMP" \
  || { rm -rf "$BIN_TMP"; error "binary download failed — check your network or grab it manually from https://github.com/unwinds/logfort/releases"; }
install -m 755 "$BIN_TMP/logfort" "$BIN_PATH"
rm -rf "$BIN_TMP"
info "installed $("$BIN_PATH" --version) to ${BIN_PATH}"

ENV_FILE="$INSTALL_DIR/logfort.env"
{
  echo "# Generated by logfort install.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "LOGFORT_LISTEN=127.0.0.1:${LISTEN_PORT}"
  echo "LOGFORT_DB_PATH=${INSTALL_DIR}/data/logfort.db"
  echo "LOGFORT_GEOIP_DB=${INSTALL_DIR}/data/geo.mmdb"
  echo "LOGFORT_ASN_DB=${INSTALL_DIR}/data/asn.mmdb"
  if [[ "$BACKEND" == "journald" ]]; then
    echo "LOGFORT_BACKEND=journald"
    echo "LOGFORT_JOURNALD_UNIT=${JOURNALD_UNIT}"
  else
    echo "LOGFORT_LOG_PATHS=${AUTH_LOG}"
  fi
  [[ -n "$FAIL2BAN_LOG" ]] && echo "LOGFORT_FAIL2BAN_LOG=${FAIL2BAN_LOG}"
  if $F2B_CONTROL; then
    echo "LOGFORT_RESPONDER_ENABLED=true"
    echo "LOGFORT_RESPONDER_BACKEND=fail2ban"
    echo "LOGFORT_FAIL2BAN_JAIL=sshd"
  fi
  [[ -n "$HOME_LAT" && -n "$HOME_LON" ]] && { echo "LOGFORT_HOME_LAT=${HOME_LAT}"; echo "LOGFORT_HOME_LON=${HOME_LON}"; }
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"
info "environment file written to $ENV_FILE"

cat > "$SYSTEMD_UNIT_FILE" <<UNIT
# Managed by logfort install.sh — safe to edit.
[Unit]
Description=LogFort — SSH & nginx attack dashboard
Documentation=https://github.com/unwinds/logfort
After=network.target

[Service]
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
Restart=on-failure
RestartSec=5
# Runs as root: reads root-owned auth logs and (optionally) talks to the
# fail2ban command socket. Hardened where root still allows it:
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
info "systemd unit written to $SYSTEMD_UNIT_FILE"
fi

# ── GeoIP / ASN downloads ─────────────────────────────────────────────────────
# download_dbip <slug> <target> — fetches the current month's DB-IP Lite file,
# falling back to the previous month when the fresh one is not published yet.
download_dbip() {
  local slug="$1" target="$2" tmp ok=false YM URL
  tmp=$(mktemp "${target}.XXXXXX")
  for YM in "$(date +%Y-%m)" "$(date -d "-1 month" +%Y-%m 2>/dev/null || date -v-1m +%Y-%m 2>/dev/null)"; do
    [[ -z "$YM" ]] && continue
    URL="https://download.db-ip.com/free/${slug}-${YM}.mmdb.gz"
    info "Downloading ${slug} ${YM}…"
    if curl -fsSL "$URL" | gunzip > "$tmp" 2>/dev/null && [[ -s "$tmp" ]]; then
      mv "$tmp" "$target"
      chmod 644 "$target"
      info "saved to $target"
      ok=true
      break
    fi
  done
  if ! $ok; then
    rm -f "$tmp"
    warn "download failed — you can fetch it later:"
    warn "  curl -fsSL \"https://download.db-ip.com/free/${slug}-$(date +%Y-%m).mmdb.gz\" | gunzip > $target"
  fi
}

ask "Download free GeoIP database for the attack map? (DB-IP Lite, CC BY 4.0) [Y/n]"
read_tty ans
if [[ ! "$ans" =~ ^[Nn]$ ]]; then
  download_dbip "dbip-city-lite" "$INSTALL_DIR/data/geo.mmdb"
fi

ask "Download free ASN database (shows the attacker's network operator)? (DB-IP ASN Lite, CC BY 4.0) [Y/n]"
read_tty ans
if [[ ! "$ans" =~ ^[Nn]$ ]]; then
  download_dbip "dbip-asn-lite" "$INSTALL_DIR/data/asn.mmdb"
fi

# ── start ─────────────────────────────────────────────────────────────────────
ask "Start logfort now? [Y/n]"
read_tty ans
if [[ ! "$ans" =~ ^[Nn]$ ]]; then
  if [[ "$INSTALL_MODE" == "docker" ]]; then
    docker compose -f "$COMPOSE_FILE" pull
    docker compose -f "$COMPOSE_FILE" up -d
    info "logfort is running on http://127.0.0.1:${LISTEN_PORT}"
    info "If the dashboard stays empty, check log access: docker logs logfort | grep -i 'source error'"
  else
    systemctl enable --now logfort
    info "logfort is running on http://127.0.0.1:${LISTEN_PORT}"
    info "Logs: journalctl -u logfort -f"
  fi
  info "Tip: access via SSH tunnel: ssh -L ${LISTEN_PORT}:127.0.0.1:${LISTEN_PORT} user@yourserver"
else
  if [[ "$INSTALL_MODE" == "docker" ]]; then
    info "Start later with: docker compose -f $COMPOSE_FILE up -d"
  else
    info "Start later with: systemctl enable --now logfort"
  fi
fi
