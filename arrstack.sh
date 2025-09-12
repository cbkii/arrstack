#!/usr/bin/env bash
# =============================================================================
#  ARR+VPN STACK INSTALLER
# =============================================================================
set -euo pipefail

# ----------------------------[ USER CONFIG ]-----------------------------------
USER_NAME="${USER:-$(id -un)}"
BASE="/home/${USER_NAME}/srv"
DOCKER_DIR="${BASE}/docker"
STACK_DIR="${BASE}/arr-stack"
BACKUP_DIR="${BASE}/backups"
PVPN_SRC="${BASE}/pvpn-backup" # Put Proton files (.conf, etc.) here

# Media/Downloads layout
MEDIA_DIR="/media/mediasmb"
DOWNLOADS_DIR="/home/${USER_NAME}/downloads"
COMPLETED_DIR="${DOWNLOADS_DIR}/completed"
MOVIES_DIR="${MEDIA_DIR}/movies"
TV_DIR="${MEDIA_DIR}/Shows"
SUBS_DIR="${MEDIA_DIR}/subs"

# qBittorrent UI credentials/port
QBT_HTTP_PORT_HOST="8080"
QBT_USER="admin"
QBT_PASS="adminadmin"

# Identity & timezone
PUID="$(id -u)"
PGID="$(id -g)"
TZ_AU="Australia/Sydney"

# Proton defaults and selection
DEFAULT_VPN_MODE="openvpn" # openvpn (preferred) | wireguard (fallback)
SERVER_COUNTRIES="Netherlands,Germany,Switzerland"
DEFAULT_COUNTRY="Australia"
PROTON_CREDS_FILE="${DOCKER_DIR}/gluetun/proton-credentials.conf"
PROTON_CREDS_FBAK="${PVPN_SRC}/proton-credentials.conf"
GLUETUN_API_KEY=""

# Service/package lists (kept at least as broad as originals)
ALL_CONTAINERS="gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr jackett transmission lidarr readarr"
ALL_NATIVE_SERVICES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common"
ALL_PACKAGES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common"

# Critical host ports we may free up
CRITICAL_PORTS="8080 8989 7878 9696 6767 8191 8000"

# Runtime flags
DRY_RUN="${DRY_RUN:-0}"
DEBUG="${DEBUG:-0}"
NO_COLOR="${NO_COLOR:-0}"

# Export for compose templating
export BASE DOCKER_DIR STACK_DIR BACKUP_DIR PVPN_SRC
export MEDIA_DIR DOWNLOADS_DIR COMPLETED_DIR MEDIA_DIR MOVIES_DIR TV_DIR SUBS_DIR
export QBT_HTTP_PORT_HOST QBT_USER QBT_PASS PUID PGID TZ_AU
export DEFAULT_VPN_MODE SERVER_COUNTRIES DEFAULT_COUNTRY PROTON_CREDS_FILE PROTON_CREDS_FBAK GLUETUN_API_KEY

# ----------------------------[ LOGGING ]---------------------------------------
if [[ "${NO_COLOR}" -eq 0 && -t 1 ]]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_DIM='\033[2m'
  C_RED='\033[31m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_BLUE='\033[36m'
else
  C_RESET=''
  C_BOLD=''
  C_DIM=''
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
fi
step() { printf "${C_BLUE}${C_BOLD}✴️ %s${C_RESET}\n" "$1"; }
note() { printf "${C_BLUE}➤ %s${C_RESET}\n" "$1"; }
ok() { printf "${C_GREEN}✔ %s${C_RESET}\n" "$1"; }
warn() { printf "${C_YELLOW}⚠ %s${C_RESET}\n" "$1"; }
err() { printf "${C_RED}✖ %s${C_RESET}\n" "$1"; }
die() {
  err "$1"
  exit 1
}
trace() { [ "$DEBUG" = "1" ] && printf "${C_DIM}[trace] %s${C_RESET}\n" "$1" || true; }
is_dry() { [[ "$DRY_RUN" = "1" ]]; }
run_cmd() { if is_dry; then note "[DRY] $*"; else eval "$@"; fi; }

# ----------------------------[ FS HELPERS ]------------------------------------
ensure_dir() {
  local d="$1"
  trace "mkdir -p $d"
  is_dry && {
    note "[DRY] mkdir -p $d"
    return
  }
  mkdir -p "$d" || {
    sudo mkdir -p "$d"
    sudo chown -R "${USER_NAME}:${USER_NAME}" "$d" || true
  }
}
atomic_write() {
  local f="$1"
  local content="$2"
  ensure_dir "$(dirname "$f")"
  if is_dry; then note "[DRY] write -> $f"; else printf "%s" "$content" >"$f"; fi
}

# ----------------------------[ PRECHECKS ]-------------------------------------
check_deps() {
  step "0A/13 Checking prerequisites"
  [[ "$(whoami)" == "${USER_NAME}" ]] || die "Run as '${USER_NAME}' (current: $(whoami))"
  for b in docker curl jq openssl; do command -v "$b" >/dev/null 2>&1 || die "Missing dependency: $b"; done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 not available"
  if ! command -v ss >/dev/null 2>&1; then
    note "Installing iproute2 for net utils"
    run_cmd sudo apt-get update -y >/dev/null 2>&1
    run_cmd sudo apt-get install -y iproute2 >/dev/null 2>&1 || true
  fi
  ok "Docker & Compose OK"
}

# ----------------------------[ CLEANUP PHASE ]---------------------------------
compose_cmd() { (
  cd "${STACK_DIR}" 2>/dev/null || return 0
  run_cmd docker compose "$@"
); }
stop_stack_if_present() {
  step "0B/13 Stopping any existing stack"
  compose_cmd down >/dev/null 2>&1 || true
}
stop_named_containers() {
  note "Removing known containers"
  for c in ${ALL_CONTAINERS}; do docker ps -a --format '{{.Names}}' | grep -q "^${c}$" && run_cmd docker rm -f "$c" >/dev/null 2>&1 || true; done
}
clear_port_conflicts() {
  note "Clearing port conflicts"
  for p in ${CRITICAL_PORTS}; do if sudo fuser "${p}/tcp" >/dev/null 2>&1; then
    warn "Killing process on :$p"
    run_cmd sudo fuser -k "${p}/tcp" >/dev/null 2>&1 || true
  fi; done
}
stop_native_services() {
  note "Stopping native services"
  for SVC in ${ALL_NATIVE_SERVICES}; do
    if systemctl list-units --all --type=service | grep -q "${SVC}.service"; then
      note "Stopping ${SVC}…"
      run_cmd sudo systemctl stop "${SVC}" >/dev/null 2>&1 || true
      run_cmd sudo systemctl disable "${SVC}" >/dev/null 2>&1 || true
      run_cmd sudo systemctl mask "${SVC}" >/dev/null 2>&1 || true
    fi
  done
  run_cmd sudo systemctl daemon-reload || true
}
fix_permissions_on_base() {
  note "Fixing permissions under ${BASE}"
  if [[ -d "${BASE}" ]]; then
    note "Removing root-owned Docker artefacts (logs/pids/locks/servers.json)"
    run_cmd sudo find "${BASE}" -name "servers.json" -exec rm -f {} \; 2>/dev/null || true
    run_cmd sudo find "${BASE}" -name "*.log" -path "*/gluetun/*" -exec rm -f {} \; 2>/dev/null || true
    run_cmd sudo find "${BASE}" -name "*.pid" -exec rm -f {} \; 2>/dev/null || true
    run_cmd sudo find "${BASE}" -name "*.lock" -exec rm -f {} \; 2>/dev/null || true
    note "chown -R ${USER_NAME}:${USER_NAME} ${BASE}"
    run_cmd sudo chown -R "${USER_NAME}:${USER_NAME}" "${BASE}" 2>/dev/null || true
    note "Standardising directory/file permissions"
    run_cmd find "${BASE}" -type d -exec chmod 755 {} \; 2>/dev/null || true
    run_cmd find "${BASE}" -type f -exec chmod 644 {} \; 2>/dev/null || true
  fi
}
clean_targeted_volumes() {
  note "Cleaning Docker volumes for arr/qB/transmission/gluetun"
  if ! is_dry; then docker volume ls -q | grep -Ei '(^|_)(sonarr|radarr|prowlarr|bazarr|jackett|lidarr|readarr|qbittorrent|transmission|gluetun)' | xargs -r docker volume rm >/dev/null 2>&1 || true; else note "[DRY] Would clean Docker volumes"; fi
}

# -------------------------[ DIRECTORIES & BACKUP ]-----------------------------
create_dirs() {
  step "1/13 Creating folders"
  ensure_dir "${STACK_DIR}"
  ensure_dir "${BACKUP_DIR}"
  for d in gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr scripts; do ensure_dir "${DOCKER_DIR}/${d}"; done
  for d in "${MEDIA_DIR}" "${DOWNLOADS_DIR}" "${COMPLETED_DIR}" "${MEDIA_DIR}" "${MOVIES_DIR}" "${TV_DIR}" "${SUBS_DIR}"; do ensure_dir "$d"; done
}
backup_configs() {
  step "2/13 Backing up ALL existing configurations"
  local TS
  TS="$(date +%Y%m%d-%H%M%S)"
  BACKUP_SUBDIR="${BACKUP_DIR}/backup-${TS}"
  ensure_dir "${BACKUP_SUBDIR}"
  # Docker configs
  for APP in qbittorrent sonarr radarr prowlarr bazarr jackett lidarr readarr transmission gluetun flaresolverr; do
    if [[ -d "${DOCKER_DIR}/${APP}" ]]; then
      run_cmd tar -C "${DOCKER_DIR}" -czf "${BACKUP_SUBDIR}/docker-${APP}-config.tgz" "${APP}" 2>/dev/null || true
      note "Saved ${BACKUP_SUBDIR}/docker-${APP}-config.tgz"
    fi
  done
  # Home configs
  for APP in qBittorrent Sonarr Radarr Prowlarr Bazarr Jackett Lidarr Readarr transmission; do
    if [[ -d "${HOME}/.config/${APP}" ]]; then
      run_cmd tar -C "${HOME}/.config" -czf "${BACKUP_SUBDIR}/home-${APP}-config.tgz" "${APP}" 2>/dev/null || true
      note "Saved ${BACKUP_SUBDIR}/home-${APP}-config.tgz"
    fi
  done
  # System configs
  NATIVE_DIRS="/var/lib/sonarr /var/lib/radarr /var/lib/prowlarr /var/lib/bazarr /var/lib/jackett /var/lib/lidarr /var/lib/readarr \
/opt/Sonarr /opt/Radarr /opt/Prowlarr /opt/Bazarr /opt/Jackett /opt/Lidarr /opt/Readarr \
/etc/transmission-daemon"
  for D in ${NATIVE_DIRS}; do if [[ -d "$D" ]]; then
    APP_NAME="$(basename "$D")"
    run_cmd sudo tar -czf "${BACKUP_SUBDIR}/system-${APP_NAME}.tgz" "$D" 2>/dev/null || true
    note "Saved ${BACKUP_SUBDIR}/system-${APP_NAME}.tgz"
  fi; done
  echo "${NATIVE_DIRS}" >"${BACKUP_SUBDIR}/_native_dirs.list"
  export NATIVE_DIRS
}
move_native_dirs() {
  step "3/13 Moving native application directories"
  local NATIVE_MOVE_DIR="${BACKUP_SUBDIR}/native-configs"
  ensure_dir "${NATIVE_MOVE_DIR}"
  for D in ${NATIVE_DIRS}; do if [[ -d "$D" ]]; then
    run_cmd sudo mv "$D" "${NATIVE_MOVE_DIR}/$(basename "$D")" 2>/dev/null || true
    note "Moved $D -> ${NATIVE_MOVE_DIR}/$(basename "$D")"
  fi; done
}
purge_native_packages() {
  step "4/13 Purging ALL native packages"
  run_cmd sudo apt-get update -y >/dev/null 2>&1 || true
  for PKG in ${ALL_PACKAGES}; do if dpkg -l | grep -q "^ii.*${PKG}"; then
    note "Purging ${PKG}…"
    run_cmd sudo apt-get purge -y "${PKG}" >/dev/null 2>&1 || true
  fi; done
  run_cmd sudo apt-get autoremove -y >/dev/null 2>&1 || true
  ok "Native packages purged"
}
final_docker_cleanup() {
  step "5/13 Final Docker cleanup pass"
  for CONTAINER in ${ALL_CONTAINERS}; do if docker ps -aq --filter "name=${CONTAINER}" | grep -q .; then run_cmd docker rm -f $(docker ps -aq --filter "name=${CONTAINER}") >/dev/null 2>&1 || true; else note "No leftover ${CONTAINER}"; fi; done
  ok "Docker containers cleaned"
}

# ---------------------------[ PROTON CREDS ]----------------------------------
ensure_creds_template() {
  step "6/13 Ensuring Proton credential file"
  ensure_dir "${DOCKER_DIR}/gluetun"
  if [[ ! -f "${PROTON_CREDS_FILE}" ]]; then
    if [[ -f "${PROTON_CREDS_FBAK}" ]]; then
      cp "$PROTON_CREDS_FBAK" "${PROTON_CREDS_FILE}"
      ok "Copied a backup to ${PROTON_CREDS_FILE}"
    else
      atomic_write "${PROTON_CREDS_FILE}" "# Proton account credentials (do NOT include +pmp here)\n# Get from https://account.proton.me/u/0/vpn/OpenVpnIKEv2\nPROTON_USER=\nPROTON_PASS=\n# Optional: WireGuard key for fallback\nWIREGUARD_PRIVATE_KEY=\nVPN_MODE=${DEFAULT_VPN_MODE}\nSERVER_COUNTRIES=${SERVER_COUNTRIES}\n"
    fi
  else
    ok "Found ${PROTON_CREDS_FILE}"
  fi
  if ! grep -q '^PROTON_USER=' "${PROTON_CREDS_FILE}" || ! grep -q '^PROTON_PASS=' "${PROTON_CREDS_FILE}"; then
    local user pass
    read -p "Proton username (without +pmp): " user
    read -s -p "Proton password: " pass
    echo
    sed -i '/^PROTON_USER=/d;/^PROTON_PASS=/d' "${PROTON_CREDS_FILE}"
    echo "PROTON_USER=${user}" >>"${PROTON_CREDS_FILE}"
    echo "PROTON_PASS=${pass}" >>"${PROTON_CREDS_FILE}"
  fi
  run_cmd chmod 600 "${PROTON_CREDS_FILE}"
}
ensure_pmp() {
  local u="$1"
  case "$u" in *+pmp) printf '%s\n' "$u" ;; *) printf '%s+pmp\n' "$u" ;; esac
}

# ---- WireGuard auto-seed from a .conf if present ----------------------------
find_wg_conf() {
  local n="${1:-proton.conf}" c
  for c in "${DOCKER_DIR}/gluetun/${n}" "${DOCKER_DIR}/gluetun"/*.conf "${PVPN_SRC}"/*.conf; do
    [[ -e "$c" ]] && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}
parse_wg_conf() {
  local f="$1" k a d
  k=$(grep -E '^[[:space:]]*PrivateKey[[:space:]]*=' "$f" | sed 's/^[^=]*=\s*//' | tr -d '\r' | sed 's/[[:space:]]*$//')
  a=$(grep -E '^[[:space:]]*Address[[:space:]]*=' "$f" | sed 's/^[^=]*=\s*//' | tr -d '\r' | sed 's/[[:space:]]*$//')
  d=$(grep -E '^[[:space:]]*DNS[[:space:]]*=' "$f" | sed 's/^[^=]*=\s*//' | tr -d '\r' | sed 's/[[:space:]]*$//')
  [[ -n "$k" ]] && [[ ${#k} -eq 44 ]] || return 1
  printf '%s\n%s\n%s\n' "$k" "$a" "$d"
}

# ------------------------------[ GLUETUN AUTH ]--------------------------------
make_gluetun_apikey() {
  step "7/13 Generating Gluetun API key"
  if docker run --rm ghcr.io/qdm12/gluetun genkey >/tmp/gl_apikey 2>/dev/null; then GLUETUN_API_KEY="$(cat /tmp/gl_apikey)"; else GLUETUN_API_KEY="$(openssl rand -base64 48)"; fi
  rm -f /tmp/gl_apikey
  ok "API key generated"
}
write_gluetun_auth() {
  step "8/13 Writing Gluetun RBAC config"
  local AUTH_DIR="${DOCKER_DIR}/gluetun/auth"
  ensure_dir "$AUTH_DIR"
  local toml='# Gluetun Control-Server RBAC config\n[[roles]]\nname="public"\nauth="none"\nroutes=["GET /v1/publicip/ip"]\n\n[[roles]]\nname="port-monitor"\nauth="apikey"\napikey="'"${GLUETUN_API_KEY}"'\nroutes=["GET /v1/publicip/ip","GET /v1/openvpn/portforwarded","GET /v1/openvpn/status","GET /v1/wireguard/portforwarded","GET /v1/wireguard/status"]\n'
  atomic_write "${AUTH_DIR}/config.toml" "$toml"
}

# ---------------------------[ PORT MONITOR ]-----------------------------------
create_pf_monitor() {
  step "9/13 Creating PF monitor script"
  local F="${DOCKER_DIR}/scripts/port-monitor.sh"
  ensure_dir "${DOCKER_DIR}/scripts"
  cat >"$F" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
QBT_HOST="localhost"; QBT_PORT="8080"; QBT_USER="${QBT_USER:-admin}"; QBT_PASS="${QBT_PASS:-adminadmin}"
GLUETUN_API="http://localhost:8000"; LOG_FILE="/config/port-monitor.log"; CHECK_INTERVAL=45; STAMP="/config/pf.port"
log(){ echo "[$(date +%F' '%T)] $*" | tee -a "$LOG_FILE"; }
get_pf(){
  local p=""
  p=$(curl -fsS "$GLUETUN_API/v1/openvpn/portforwarded" | jq -r '.port//empty' 2>/dev/null || true)
  [[ -n "$p" ]] || p=$(curl -fsS "$GLUETUN_API/v1/wireguard/portforwarded" | jq -r '.port//empty' 2>/dev/null || true)
  echo "$p" | grep -E '^[0-9]+$' | awk '$1>1024 && $1<65536{print$1}'
}
get_qbt(){ curl -fsS "http://${QBT_HOST}:${QBT_PORT}/api/v2/app/preferences" --data "username=${QBT_USER}&password=${QBT_PASS}"|jq -r '.listen_port//empty'||true; }
set_qbt(){ local np="$1"; curl -fsS "http://${QBT_HOST}:${QBT_PORT}/api/v2/app/setPreferences" --data "username=${QBT_USER}&password=${QBT_PASS}" --data-urlencode "json={\"listen_port\":${np},\"upnp\":false}" >/dev/null 2>&1; }
main(){ log "PF monitor started"; while :; do pf="$(get_pf||true)"; if [ -n "$pf" ]; then cur="$(get_qbt||true)"; if [ "$cur" != "$pf" ]; then log "Updating qB listen port ${cur:-N/A} -> $pf"; set_qbt "$pf" && echo "$pf" >"$STAMP"; else [ -f "$STAMP" ] || echo "$pf" >"$STAMP"; log "qB listen port already $pf"; fi; else log "No forwarded port yet"; rm -f "$STAMP"; fi; sleep "$CHECK_INTERVAL"; done }
main "$@"
SCRIPT
  run_cmd chmod +x "$F"
  ok "Wrote $F"
}

# ------------------------------[ .ENV FILE ]-----------------------------------
write_env() {
  step "10/13 Writing stack .env"
  local envf="${STACK_DIR}/.env"
  ensure_dir "${STACK_DIR}"
  local PU="" PP="" WG="" VM="${DEFAULT_VPN_MODE}" CN="${SERVER_COUNTRIES}"
  if [[ -f "${PROTON_CREDS_FILE}" ]]; then
    PU="$(grep -E '^PROTON_USER=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(grep -E '^PROTON_PASS=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    WG="$(grep -E '^WIREGUARD_PRIVATE_KEY=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    VM="$(grep -E '^VPN_MODE=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || echo "${DEFAULT_VPN_MODE}")"
    CN="$(grep -E '^SERVER_COUNTRIES=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || echo "${SERVER_COUNTRIES}")"
  fi
  local OPENVPN_USER=""
  [[ -n "$PU" ]] && OPENVPN_USER="$(ensure_pmp "$PU")"
  cat >"${envf}" <<EOF
# IDs & timezone
PUID=${PUID}
PGID=${PGID}
TZ=${TZ_AU}

# Gluetun Control-Server API key
GLUETUN_API_KEY=${GLUETUN_API_KEY}

# qBittorrent
QBT_HTTP_PORT_HOST=${QBT_HTTP_PORT_HOST}
QBT_USER=${QBT_USER}
QBT_PASS=${QBT_PASS}

# Paths
BASE=${BASE}
DOCKER_DIR=${DOCKER_DIR}
MEDIA_DIR=${MEDIA_DIR}
DOWNLOADS_DIR=${DOWNLOADS_DIR}
COMPLETED_DIR=${COMPLETED_DIR}
MOVIES_DIR=${MOVIES_DIR}
TV_DIR=${TV_DIR}
SUBS_DIR=${SUBS_DIR}

# ProtonVPN config
VPN_MODE=${VM}
SERVER_COUNTRIES=${CN}
PROTON_USER=${PU}
PROTON_PASS=${PP}
OPENVPN_USER=${OPENVPN_USER}

# WireGuard fallback
WIREGUARD_PRIVATE_KEY=${WG}
EOF
  run_cmd chmod 600 "${envf}"
  ok "Wrote ${envf}"
}

# ---------------------------[ COMPOSE FILE ]-----------------------------------
write_compose() {
  step "11/13 Writing docker-compose.yml"
  cat >"${STACK_DIR}/docker-compose.yml" <<'YAML'
services:
  gluetun:
    image: qmcgaw/gluetun:latest
    container_name: gluetun
    cap_add: ["NET_ADMIN"]
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      - TZ=${TZ}
      - VPN_SERVICE_PROVIDER=protonvpn
      - VPN_TYPE=${VPN_MODE}
      - OPENVPN_USER=${OPENVPN_USER}
      - OPENVPN_PASSWORD=${PROTON_PASS}
      - WIREGUARD_PRIVATE_KEY=${WIREGUARD_PRIVATE_KEY}
      - WIREGUARD_MTU=1320
      - VPN_PORT_FORWARDING=on
      - VPN_PORT_FORWARDING_PROVIDER=protonvpn
      - PORT_FORWARD_ONLY=on
      - SERVER_COUNTRIES=${SERVER_COUNTRIES}
      - FREE_ONLY=off
      # DNS & stability
      - DOT=off
      - DOT_IPV6=off
      - UPDATER_PERIOD=
      - HEALTH_TARGET_ADDRESS=1.1.1.1:443
      # Control server (RBAC)
      - HTTP_CONTROL_SERVER_ADDRESS=0.0.0.0:8000
      - HTTP_CONTROL_SERVER_LOG=off
      - HTTP_CONTROL_SERVER_AUTH_FILE=/gluetun/auth/config.toml
    volumes:
      - ${DOCKER_DIR}/gluetun:/gluetun
      - ${DOCKER_DIR}/gluetun/auth/config.toml:/gluetun/auth/config.toml:ro
    ports:
      - "127.0.0.1:8000:8000"          # Gluetun control API (host-local)
      - "${QBT_HTTP_PORT_HOST}:8080"   # qB WebUI via gluetun namespace
      - "8989:8989"                    # Sonarr
      - "7878:7878"                    # Radarr
      - "9696:9696"                    # Prowlarr
      - "6767:6767"                    # Bazarr
      - "8191:8191"                    # FlareSolverr
    healthcheck:
      test: |
        curl -fsS http://localhost:8000/v1/publicip/ip &&
        curl -fsS http://localhost:8000/v1/openvpn/status &&
        curl -fsS http://localhost:8000/v1/openvpn/portforwarded | jq -e '.port | tonumber > 1024'
      interval: 30s
      timeout: 15s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    container_name: qbittorrent
    network_mode: "service:gluetun"
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TZ}
      - WEBUI_PORT=8080
      - DOCKER_MODS=ghcr.io/gabe565/linuxserver-mod-vuetorrent
      - VPN_TYPE=${VPN_MODE}
    volumes:
      - ${DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
      - ${DOCKER_DIR}/scripts:/scripts:ro
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:8080/api/v2/app/version >/dev/null && ( [ \"$VPN_TYPE\" != 'openvpn' ] || [ -f /config/pf.port ] )"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    command: |
      /bin/bash -c '
        if [ "$VPN_TYPE" = "openvpn" ]; then /scripts/port-monitor.sh & fi
        exec /init
      '
    restart: unless-stopped

  sonarr:
    image: ghcr.io/hotio/sonarr:release
    container_name: sonarr
    network_mode: "service:gluetun"
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TZ}
    volumes:
      - ${DOCKER_DIR}/sonarr:/config
      - ${TV_DIR}:/tv
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      prowlarr:
        condition: service_healthy
      qbittorrent:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:8989 >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  radarr:
    image: ghcr.io/hotio/radarr:release
    container_name: radarr
    network_mode: "service:gluetun"
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TZ}
    volumes:
      - ${DOCKER_DIR}/radarr:/config
      - ${MOVIES_DIR}:/movies
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      prowlarr:
        condition: service_healthy
      qbittorrent:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:7878 >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  prowlarr:
    image: lscr.io/linuxserver/prowlarr:latest
    container_name: prowlarr
    network_mode: "service:gluetun"
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TZ}
    volumes:
      - ${DOCKER_DIR}/prowlarr:/config
    depends_on:
      qbittorrent:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:9696 >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  bazarr:
    image: lscr.io/linuxserver/bazarr:latest
    container_name: bazarr
    network_mode: "service:gluetun"
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TZ}
    volumes:
      - ${DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
      - ${SUBS_DIR}:/subs
    depends_on:
      sonarr:
        condition: service_healthy
      radarr:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:6767 >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  flaresolverr:
    image: ghcr.io/flaresolverr/flaresolverr:latest
    container_name: flaresolverr
    network_mode: "service:gluetun"
    environment:
      - LOG_LEVEL=info
    depends_on:
      prowlarr:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:8191 >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped
YAML
  ok "Wrote ${STACK_DIR}/docker-compose.yml"
}

# ------------------------------[ STARTUP ]-------------------------------------
validate_creds_or_die() {
  local PU PP ENVF="${STACK_DIR}/.env"
  PU="$(grep -E '^PROTON_USER=' "$ENVF" | cut -d= -f2- || true)"
  PP="$(grep -E '^PROTON_PASS=' "$ENVF" | cut -d= -f2- || true)"
  if [[ -z "${PU}" || -z "${PP}" ]]; then
    err "Proton credentials missing. Edit ${PROTON_CREDS_FILE} then re-run."
    exit 2
  fi
  local OU
  OU="$(grep -E '^OPENVPN_USER=' "$ENVF" | cut -d= -f2- || true)"
  if [[ -z "$OU" || "$OU" != *+pmp ]]; then
    warn "Fixing OPENVPN_USER to include +pmp"
    sed -i '/^OPENVPN_USER=/d' "$ENVF"
    echo "OPENVPN_USER=$(ensure_pmp "$PU")" >>"$ENVF"
  fi
}
pull_images() {
  step "12/13 Pulling images"
  compose_cmd pull || warn "Pull failed; will rely on up"
}
start_with_checks() {
  step "13/13 Starting the stack with enhanced health monitoring"
  validate_creds_or_die
  local MAX_RETRIES=5 RETRY=0
  while [[ $RETRY -lt $MAX_RETRIES ]]; do
    note "→ Attempt $((RETRY + 1))/${MAX_RETRIES}"
    compose_cmd up -d gluetun || warn "gluetun up failed"
    local waited=0 HEALTH="unknown" IP="" PF=""
    while [[ $waited -lt 180 ]]; do
      HEALTH="$(docker inspect gluetun --format='{{.State.Health.Status}}' 2>/dev/null || echo unknown)"
      IP="$(docker exec gluetun wget -qO- http://localhost:8000/v1/publicip/ip 2>/dev/null || true)"
      PF="$(docker exec gluetun wget -qO- http://localhost:8000/v1/openvpn/portforwarded 2>/dev/null | grep -o '[0-9]\+' || true)"
      [[ "$HEALTH" = healthy && -n "$IP" && -n "$PF" && "$PF" -gt 1024 ]] && break
      sleep 5
      waited=$((waited + 5))
    done
    if [[ "$HEALTH" = healthy && -n "$IP" ]]; then
      ok "Gluetun healthy; IP: ${IP}${PF:+, PF: ${PF}}"
      break
    fi
    warn "Gluetun not healthy yet; down & retry"
    compose_cmd down >/dev/null 2>&1 || true
    clear_port_conflicts
    RETRY=$((RETRY + 1))
  done
  if [[ "$HEALTH" != healthy ]]; then
    err "Gluetun did not achieve connectivity; check: docker logs gluetun"
    exit 3
  fi
  compose_cmd up -d qbittorrent prowlarr sonarr radarr bazarr flaresolverr || die "Failed to start stack"
  compose_cmd ps || true
  note "Public IP:"
  curl -fsS http://127.0.0.1:8000/v1/publicip/ip || true
  note "Forwarded port:"
  curl -fsS http://127.0.0.1:8000/v1/openvpn/portforwarded || true
}

# ------------------------------[ HELPERS ]-------------------------------------
install_pvpn_helper() {
  local F="${BASE}/.vpn_aliases"
  cat >"$F" <<'PVPN'
# Helper for ProtonVPN + Gluetun control
pvpn(){
  local cmd="${1:-}"; shift || true
  local BASE="/home/${USER:-$(id -un)}/srv"; local STACK_DIR="${BASE}/arr-stack"; local ENV_FILE="${STACK_DIR}/.env"; local CREDS_FILE="${BASE}/docker/gluetun/proton-credentials.conf"
  _get(){ grep -E "^$1=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || true; }
  _restart(){ (cd "$STACK_DIR" && docker compose --env-file "$ENV_FILE" restart gluetun) }
  case "$cmd" in
    c|connect) echo "Starting gluetun + qB…"; (cd "$STACK_DIR" && docker compose --env-file "$ENV_FILE" up -d gluetun qbittorrent) || return 1;;
    r|reconnect) _restart || return 1;;
    creds) local user pass; read -p "Proton username (without +pmp): " user; read -s -p "Password: " pass; echo; sed -i '/^PROTON_USER=/d;/^PROTON_PASS=/d' "$CREDS_FILE" 2>/dev/null || true; echo "PROTON_USER=${user}" >>"$CREDS_FILE"; echo "PROTON_PASS=${pass}" >>"$CREDS_FILE"; sed -i '/^OPENVPN_USER=/d' "$ENV_FILE" 2>/dev/null || true; echo "OPENVPN_USER=${user}+pmp" >>"$ENV_FILE"; echo "PROTON_PASS=${pass}" >>"$ENV_FILE"; echo "Updated creds. Restarting gluetun…"; _restart;;
    s|status) echo "-- Gluetun --"; docker ps --filter name=gluetun --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | tail -n +1; echo "-- Public IP --"; curl -fsS localhost:8000/v1/publicip/ip || echo N/A; echo "-- Forwarded port --"; curl -fsS localhost:8000/v1/openvpn/portforwarded || echo N/A; echo "-- qB listen --"; curl -fsS "http://127.0.0.1:$( _get QBT_HTTP_PORT_HOST )/api/v2/app/preferences" --data "username=${QBT_USER:-admin}&password=${QBT_PASS:-adminadmin}" 2>/dev/null | jq -r '.listen_port // empty' || echo N/A;;
    portsync) local pf; pf=$(curl -fsS localhost:8000/v1/openvpn/portforwarded 2>/dev/null | jq -r '.port // empty' || true); [ -n "$pf" ] && curl -fsS "http://127.0.0.1:$( _get QBT_HTTP_PORT_HOST )/api/v2/app/setPreferences" --data "username=${QBT_USER:-admin}&password=${QBT_PASS:-adminadmin}" --data-urlencode "json={\"listen_port\":${pf},\"upnp\":false}" >/dev/null 2>&1 && echo "qB port set to ${pf}" || echo "No PF yet";;
    *) cat <<USAGE
Usage: pvpn <command>
  c, connect         Start gluetun + qB
  r, reconnect       Restart gluetun
  creds              Update Proton creds (enforces +pmp)
  s, status          Show public IP, forwarded port, qB listen port
  portsync           Sync qB listen port now
USAGE
       ;;
  esac
}
PVPN
  local SHELLRC="/home/${USER_NAME}/.bashrc"
  local SRC="[ -f ${F} ] && source ${F}"
  grep -Fq "$SRC" "$SHELLRC" 2>/dev/null || echo "$SRC" >>"$SHELLRC"
  ok "pvpn helper installed"
}

# --------------------------------[ MAIN ]--------------------------------------
main() {
  step "ARR+VPN merged installer"
  check_deps
  stop_stack_if_present
  stop_named_containers
  clear_port_conflicts
  stop_native_services
  fix_permissions_on_base
  clean_targeted_volumes
  create_dirs
  backup_configs
  move_native_dirs
  purge_native_packages
  final_docker_cleanup
  ensure_creds_template
  make_gluetun_apikey
  write_gluetun_auth
  create_pf_monitor
  write_env
  # Optional: auto-seed WG key from a .conf if none set
  if ! grep -q '^WIREGUARD_PRIVATE_KEY=' "${STACK_DIR}/.env" || [[ -z "$(grep -E '^WIREGUARD_PRIVATE_KEY=' "${STACK_DIR}/.env" | cut -d= -f2-)" ]]; then
    if CONF="$(find_wg_conf || true)"; then
      if read -r K A D < <(parse_wg_conf "$CONF" 2>/dev/null); then
        sed -i '/^WIREGUARD_PRIVATE_KEY=/d;/^WIREGUARD_ADDRESSES=/d;/^DNS_ADDRESS=/d' "${STACK_DIR}/.env"
        echo "WIREGUARD_PRIVATE_KEY=${K}" >>"${STACK_DIR}/.env"
        [ -n "$A" ] && echo "WIREGUARD_ADDRESSES=${A}" >>"${STACK_DIR}/.env"
        [ -n "$D" ] && echo "DNS_ADDRESS=${D}" >>"${STACK_DIR}/.env"
        ok "Seeded WG from $(basename "$CONF")"
      fi
    fi
  fi
  write_compose
  pull_images
  start_with_checks
  install_pvpn_helper
  echo
  ok "Done. Next steps:"
  echo "  • Edit ${PROTON_CREDS_FILE} (username WITHOUT +pmp) if you haven't already."
  echo "  • qB Web UI: http://<host>:${QBT_HTTP_PORT_HOST} (default ${QBT_USER}/${QBT_PASS})."
}

main "$@"
