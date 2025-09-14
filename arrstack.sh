#!/usr/bin/env bash
# =============================================================================
#  ARR+VPN STACK INSTALLER
# =============================================================================
set -euo pipefail

# ----------------------------[ USER CONFIG ]-----------------------------------
USER_NAME="${USER:-$(id -un)}"
ARR_BASE="/home/${USER_NAME}/srv"
ARR_DOCKER_DIR="${ARR_BASE}/docker"
ARR_STACK_DIR="${ARR_BASE}/arrstack"
ARR_BACKUP_DIR="${ARR_BASE}/backups"
ARR_VPNCONFS_DIR="${ARR_BASE}/wg-configs" # Put Proton files (.conf, etc.) here

# Local IP for binding services
LAN_IP="192.168.1.50" # set to your host's LAN IP
GLUETUN_CONTROL_PORT="8000" # Gluetun control server port
GLUETUN_CONTROL_HOST="127.0.0.1" # Host used for Gluetun control server checks

# Media/Downloads layout
MEDIA_DIR="/media/mediasmb"
DOWNLOADS_DIR="/home/${USER_NAME}/downloads"
COMPLETED_DIR="${DOWNLOADS_DIR}/completed"
MOVIES_DIR="${MEDIA_DIR}/Movies"
TV_DIR="${MEDIA_DIR}/Shows"
SUBS_DIR="${MEDIA_DIR}/subs"

# qBittorrent UI credentials/ports
QBT_WEBUI_PORT="8080"     # qBittorrent WebUI port inside container
QBT_HTTP_PORT_HOST="8080" # host port mapped to qBittorrent
QBT_USER=""
QBT_PASS=""

# Service ports (host:container)
SONARR_PORT="8989"
RADARR_PORT="7878"
PROWLARR_PORT="9696"
BAZARR_PORT="6767"
FLARESOLVERR_PORT="8191"

# Identity & timezone
PUID="$(id -u)"
PGID="$(id -g)"
TIMEZONE="Australia/Sydney"

# Proton defaults and selection
DEFAULT_VPN_MODE="openvpn" # openvpn (preferred) | wireguard (fallback)
SERVER_COUNTRIES="Netherlands,Germany,Switzerland,Australia,Spain,United States"
DEFAULT_COUNTRY="Australia"
PROTON_CREDS_FILE="${ARR_DOCKER_DIR}/gluetun/proton-credentials.conf"
PROTON_CREDS_FBAK="${ARR_VPNCONFS_DIR}/proton-credentials.conf"
GLUETUN_API_KEY=""

# Service/package lists (kept at least as broad as originals)
ALL_CONTAINERS="gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr jackett transmission lidarr readarr"
ALL_NATIVE_SERVICES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common"
ALL_PACKAGES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common"

# Critical host ports we may free up
CRITICAL_PORTS="${QBT_HTTP_PORT_HOST} ${SONARR_PORT} ${RADARR_PORT} ${PROWLARR_PORT} ${BAZARR_PORT} ${FLARESOLVERR_PORT} ${GLUETUN_CONTROL_PORT}"

# Runtime flags
DRY_RUN="${DRY_RUN:-0}"
DEBUG="${DEBUG:-0}"
NO_COLOR="${NO_COLOR:-0}"
VPN_MODE="${DEFAULT_VPN_MODE}"

# Export for compose templating
export ARR_BASE ARR_DOCKER_DIR ARR_STACK_DIR ARR_BACKUP_DIR ARR_VPNCONFS_DIR
export MEDIA_DIR DOWNLOADS_DIR COMPLETED_DIR MEDIA_DIR MOVIES_DIR TV_DIR SUBS_DIR
export QBT_WEBUI_PORT QBT_HTTP_PORT_HOST QBT_USER QBT_PASS LAN_IP GLUETUN_CONTROL_PORT GLUETUN_CONTROL_HOST PUID PGID TIMEZONE
export SONARR_PORT RADARR_PORT PROWLARR_PORT BAZARR_PORT FLARESOLVERR_PORT
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
# shellcheck disable=SC2015
trace() { [ "$DEBUG" = "1" ] && printf "${C_DIM}[trace] %s${C_RESET}\n" "$1" || true; }
is_dry() { [[ "$DRY_RUN" = "1" ]]; }
# shellcheck disable=SC2294
run_cmd() { if is_dry; then note "[DRY] $*"; else eval "$@"; fi; }

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --openvpn) VPN_MODE="openvpn" ;;
      --wireguard) VPN_MODE="wireguard" ;;
    esac
    shift
  done
}

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
  step "0A/12 Checking prerequisites"
  [[ "$(whoami)" == "${USER_NAME}" ]] || die "Run as '${USER_NAME}' (current: $(whoami))"
  for b in docker wget curl openssl; do command -v "$b" >/dev/null 2>&1 || die "Missing dependency: $b"; done
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
  cd "${ARR_STACK_DIR}" 2>/dev/null || return 0
  run_cmd docker compose "$@"
); }
stop_stack_if_present() {
  step "0B/12 Stopping any existing stack"
  compose_cmd down >/dev/null 2>&1 || true
}
stop_named_containers() {
  note "Removing known containers"
  # shellcheck disable=SC2015
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
  note "Fixing permissions under ${ARR_BASE}"
  if [[ -d "${ARR_BASE}" ]]; then
    note "Removing root-owned Docker artefacts (logs/pids/locks/servers.json)"
    run_cmd sudo find "${ARR_BASE}" -name "servers.json" -exec rm -f {} \; 2>/dev/null || true
    run_cmd sudo find "${ARR_BASE}" -name "*.log" -path "*/gluetun/*" -exec rm -f {} \; 2>/dev/null || true
    run_cmd sudo find "${ARR_BASE}" -name "*.pid" -exec rm -f {} \; 2>/dev/null || true
    run_cmd sudo find "${ARR_BASE}" -name "*.lock" -exec rm -f {} \; 2>/dev/null || true
    note "chown -R ${USER_NAME}:${USER_NAME} ${ARR_BASE}"
    run_cmd sudo chown -R "${USER_NAME}:${USER_NAME}" "${ARR_BASE}" 2>/dev/null || true
    note "Standardising directory/file permissions"
    run_cmd find "${ARR_BASE}" -type d -exec chmod 755 {} \; 2>/dev/null || true
    run_cmd find "${ARR_BASE}" -type f -exec chmod 644 {} \; 2>/dev/null || true
  fi
}
clean_targeted_volumes() {
  note "Cleaning Docker volumes for arr/qB/transmission/gluetun"
  if ! is_dry; then docker volume ls -q | grep -Ei '(^|_)(sonarr|radarr|prowlarr|bazarr|jackett|lidarr|readarr|qbittorrent|transmission|gluetun)' | xargs -r docker volume rm >/dev/null 2>&1 || true; else note "[DRY] Would clean Docker volumes"; fi
}

# -------------------------[ DIRECTORIES & BACKUP ]-----------------------------
create_dirs() {
  step "1/12 Creating folders"
  ensure_dir "${ARR_STACK_DIR}"
  ensure_dir "${ARR_BACKUP_DIR}"
  for d in gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr; do ensure_dir "${ARR_DOCKER_DIR}/${d}"; done
  for d in "${MEDIA_DIR}" "${DOWNLOADS_DIR}" "${DOWNLOADS_DIR}/incomplete" "${COMPLETED_DIR}" "${MEDIA_DIR}" "${MOVIES_DIR}" "${TV_DIR}" "${SUBS_DIR}"; do ensure_dir "$d"; done
}
backup_configs() {
  step "2/12 Backing up ALL existing configurations"
  local TS
  TS="$(date +%Y%m%d-%H%M%S)"
  BACKUP_SUBDIR="${ARR_BACKUP_DIR}/backup-${TS}"
  ensure_dir "${BACKUP_SUBDIR}"
  # Docker configs
  for APP in qbittorrent sonarr radarr prowlarr bazarr jackett lidarr readarr transmission gluetun flaresolverr; do
    if [[ -d "${ARR_DOCKER_DIR}/${APP}" ]]; then
      run_cmd tar -C "${ARR_DOCKER_DIR}" -czf "${BACKUP_SUBDIR}/docker-${APP}-config.tgz" "${APP}" 2>/dev/null || true
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
  step "3/12 Moving native application directories"
  local NATIVE_MOVE_DIR="${BACKUP_SUBDIR}/native-configs"
  ensure_dir "${NATIVE_MOVE_DIR}"
  for D in ${NATIVE_DIRS}; do if [[ -d "$D" ]]; then
    run_cmd sudo mv "$D" "${NATIVE_MOVE_DIR}/$(basename "$D")" 2>/dev/null || true
    note "Moved $D -> ${NATIVE_MOVE_DIR}/$(basename "$D")"
  fi; done
}
purge_native_packages() {
  step "4/12 Purging ALL native packages"
  run_cmd sudo apt-get update -y >/dev/null 2>&1 || true
  for PKG in ${ALL_PACKAGES}; do if dpkg -l | grep -q "^ii.*${PKG}"; then
    note "Purging ${PKG}…"
    run_cmd sudo apt-get purge -y "${PKG}" >/dev/null 2>&1 || true
  fi; done
  run_cmd sudo apt-get autoremove -y >/dev/null 2>&1 || true
  ok "Native packages purged"
}
final_docker_cleanup() {
  step "5/12 Final Docker cleanup pass"
  for CONTAINER in ${ALL_CONTAINERS}; do
    if docker ps -aq --filter "name=${CONTAINER}" | grep -q .; then
      run_cmd docker rm -f "$(docker ps -aq --filter "name=${CONTAINER}")" >/dev/null 2>&1 || true
    else
      note "No leftover ${CONTAINER}"
    fi
  done
  ok "Docker containers cleaned"
}

# ---------------------------[ PROTON CREDS ]----------------------------------
ensure_creds_template() {
  step "6/12 Ensuring Proton credential file"
  ensure_dir "${ARR_DOCKER_DIR}/gluetun"
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
    IFS= read -r -p "Proton username (without +pmp): " user
    IFS= read -r -s -p "Proton password: " pass
    printf '\n'
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
# find_wg_conf [name]
#
# Locate a WireGuard configuration file. Optionally pass a specific
# filename (default: "proton.conf"). Returns the first existing path.
find_wg_conf() {
  local n="proton.conf" c
  [ $# -gt 0 ] && n="$1"
  for c in "${ARR_DOCKER_DIR}/gluetun/${n}" \
   "${ARR_DOCKER_DIR}/gluetun"/wg*.conf \
   "${ARR_VPNCONFS_DIR}"/wg*.conf \
   "${ARR_VPNCONFS_DIR}/${n}"; do
    [[ -e "$c" ]] && {
      printf '%s\n' "$c"
      return 0
    }
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
  step "7/12 Generating Gluetun API key"
  if [[ -f "${ARR_STACK_DIR}/.env" ]]; then
    GLUETUN_API_KEY="$(grep -E '^GLUETUN_API_KEY=' "${ARR_STACK_DIR}/.env" | cut -d= -f2- || true)"
  fi
  if [[ -z "${GLUETUN_API_KEY}" ]]; then
    if docker run --rm ghcr.io/qdm12/gluetun genkey >/tmp/gl_apikey 2>/dev/null; then
      GLUETUN_API_KEY="$(cat /tmp/gl_apikey)"
    else
      GLUETUN_API_KEY="$(openssl rand -base64 48)"
    fi
    rm -f /tmp/gl_apikey
    ok "API key generated"
  else
    ok "Reusing existing API key"
  fi
}
write_gluetun_auth() {
  step "8/12 Writing Gluetun RBAC config"
  local AUTH_DIR="${ARR_DOCKER_DIR}/gluetun/auth"
  ensure_dir "$AUTH_DIR"
  local toml='# Gluetun Control-Server RBAC config\n[[roles]]\nname="readonly"\nauth="basic"\nusername="gluetun"\npassword="'"${GLUETUN_API_KEY}"'\nroutes=["GET /v1/openvpn/status","GET /v1/wireguard/status","GET /v1/publicip/ip","GET /v1/openvpn/portforwarded"]\n'
  atomic_write "${AUTH_DIR}/config.toml" "$toml"
  run_cmd chmod 600 "${AUTH_DIR}/config.toml"
}

# ---------------------------[ PORT MONITOR ]-----------------------------------
# ------------------------------[ .ENV FILE ]-----------------------------------
write_env() {
  step "9/12 Writing stack .env"
  local envf="${ARR_STACK_DIR}/.env"
  ensure_dir "${ARR_STACK_DIR}"
  local PU="" PP="" WG="" CN="${SERVER_COUNTRIES}"
  if [[ -f "${PROTON_CREDS_FILE}" ]]; then
    PU="$(grep -E '^PROTON_USER=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(grep -E '^PROTON_PASS=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    WG="$(grep -E '^WIREGUARD_PRIVATE_KEY=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    CN="$(grep -E '^SERVER_COUNTRIES=' "${PROTON_CREDS_FILE}" | cut -d= -f2- | tr -d '"' || echo "${SERVER_COUNTRIES}")"
  fi
  cat >"${envf}" <<EOF
# IDs & timezone
PUID=${PUID}
PGID=${PGID}
TIMEZONE=${TIMEZONE}

# Gluetun Control-Server API key
GLUETUN_API_KEY=${GLUETUN_API_KEY}

# Network and qBittorrent
GLUETUN_CONTROL_PORT=${GLUETUN_CONTROL_PORT}
QBT_HTTP_PORT_HOST=${QBT_HTTP_PORT_HOST}
QBT_WEBUI_PORT=${QBT_WEBUI_PORT}
GLUETUN_CONTROL_HOST=${GLUETUN_CONTROL_HOST}
QBT_USER=${QBT_USER}
QBT_PASS=${QBT_PASS}
LAN_IP=${LAN_IP}
SONARR_PORT=${SONARR_PORT}
RADARR_PORT=${RADARR_PORT}
PROWLARR_PORT=${PROWLARR_PORT}
BAZARR_PORT=${BAZARR_PORT}
FLARESOLVERR_PORT=${FLARESOLVERR_PORT}

# Paths
ARR_BASE=${ARR_BASE}
ARR_STACK_DIR=${ARR_STACK_DIR}
ARR_DOCKER_DIR=${ARR_DOCKER_DIR}
ARR_BACKUP_DIR=${ARR_BACKUP_DIR}
MEDIA_DIR=${MEDIA_DIR}
DOWNLOADS_DIR=${DOWNLOADS_DIR}
COMPLETED_DIR=${COMPLETED_DIR}
MOVIES_DIR=${MOVIES_DIR}
TV_DIR=${TV_DIR}
SUBS_DIR=${SUBS_DIR}

# ProtonVPN config
VPN_MODE=${VPN_MODE}
VPN_TYPE=${VPN_MODE}
SERVER_COUNTRIES=${CN}
UPDATER_PERIOD=24h
EOF
  if [[ "${VPN_MODE}" = "openvpn" ]]; then
    {
      echo "PROTON_USER=${PU}"
      echo "PROTON_PASS=${PP}"
      echo "OPENVPN_USER=$(ensure_pmp "${PU}")"
      echo "OPENVPN_PASSWORD=${PP}"
    } >>"${envf}"
  else
    {
      echo "WIREGUARD_PRIVATE_KEY=${WG}"
      echo "WIREGUARD_ADDRESSES="
      echo "VPN_DNS_ADDRESS="
      echo "WIREGUARD_MTU=1320"
    } >>"${envf}"
  fi
  run_cmd chmod 600 "${envf}"
  ok "Wrote ${envf}"
}

# Warn if LAN_IP is 0.0.0.0 which exposes services on all interfaces
warn_lan_ip() {
  if [ "${LAN_IP}" = "0.0.0.0" ]; then
    echo "WARNING: LAN_IP is set to 0.0.0.0 — this would expose the Gluetun API publicly. Set LAN_IP to your LAN interface IP (e.g. 192.168.1.10) for LAN-only access." >&2
  fi
}

# Populate WireGuard variables from a Proton .conf and fail if malformed when VPN_MODE=wireguard
seed_wireguard_from_conf() {
  local VM CONF K A D
  VM="$(grep -E '^VPN_MODE=' "${ARR_STACK_DIR}/.env" | cut -d= -f2- || echo "${DEFAULT_VPN_MODE}")"
  if [[ "$VM" = "wireguard" ]]; then
    CONF="$(find_wg_conf "proton.conf" 2>/dev/null)" || die "VPN_MODE=wireguard but no WireGuard .conf found in ${ARR_VPNCONFS_DIR} or ${ARR_DOCKER_DIR}/gluetun"
    read -r K A D < <(parse_wg_conf "$CONF" 2>/dev/null) || die "Malformed WireGuard config: $CONF"
    sed -i '/^WIREGUARD_PRIVATE_KEY=/d;/^WIREGUARD_ADDRESSES=/d;/^VPN_DNS_ADDRESS=/d' "${ARR_STACK_DIR}/.env"
    echo "WIREGUARD_PRIVATE_KEY=${K}" >>"${ARR_STACK_DIR}/.env"
    [ -n "$A" ] && echo "WIREGUARD_ADDRESSES=${A}" >>"${ARR_STACK_DIR}/.env"
    [ -n "$D" ] && echo "VPN_DNS_ADDRESS=${D}" >>"${ARR_STACK_DIR}/.env"
    ok "Seeded WG from $(basename "$CONF")"
  fi
}

# Pre-seed qBittorrent credentials if provided
preseed_qbt_config() {
  if [[ -n "$QBT_USER" && -n "$QBT_PASS" ]]; then
    local cfg="${ARR_DOCKER_DIR}/qbittorrent/qBittorrent.conf"
    if [[ ! -f "$cfg" ]]; then
      ensure_dir "$(dirname "$cfg")"
      local hash
      hash=$(
        python3 - <<'PY'
import os,base64,hashlib
p=os.environ['QBT_PASS'].encode()
salt=os.urandom(16)
dk=hashlib.pbkdf2_hmac('sha512',p,salt,100000,64)
print('@ByteArray('+base64.b64encode(dk+salt).decode()+')')
PY
      )
      local content="[AutoRun]\nenabled=false\nprogram=\n\n[LegalNotice]\nAccepted=true\n\n[Preferences]\nConnection\\UPnP=false\nConnection\\PortRangeMin=6881\nDownloads\\SavePath=/completed/\nDownloads\\ScanDirsV2=@Variant(\\0\\0\\0\\x1c\\0\\0\\0\\0)\nDownloads\\TempPath=/downloads/incomplete/\nDownloads\\TempPathEnabled=true\nWebUI\\Address=*\nWebUI\\ServerDomains=*\nWebUI\\Username=${QBT_USER}\nWebUI\\Password_PBKDF2=${hash}\n"
      atomic_write "$cfg" "$content"
      run_cmd chmod 600 "$cfg"
      ok "Preseeded qBittorrent credentials"
    fi
  fi
}

# ---------------------------[ COMPOSE FILE ]-----------------------------------
write_compose() {
  step "10/12 Writing docker-compose.yml"
  {
    cat <<'YAML'
services:
  gluetun:
    image: qmcgaw/gluetun:latest
    container_name: gluetun
    cap_add: ["NET_ADMIN"]
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      - TZ=${TIMEZONE}
      - VPN_SERVICE_PROVIDER=protonvpn
      - VPN_TYPE=${VPN_TYPE}
YAML
    if [ "${VPN_MODE}" = "openvpn" ]; then
      cat <<'YAML'
      - OPENVPN_USER=${OPENVPN_USER}
      - OPENVPN_PASSWORD=${OPENVPN_PASSWORD}
YAML
    else
      cat <<'YAML'
      - WIREGUARD_PRIVATE_KEY=${WIREGUARD_PRIVATE_KEY}
      - WIREGUARD_ADDRESSES=${WIREGUARD_ADDRESSES}
      - WIREGUARD_MTU=${WIREGUARD_MTU}
      - VPN_DNS_ADDRESS=${VPN_DNS_ADDRESS}
YAML
    fi
    cat <<'YAML'
      - VPN_PORT_FORWARDING=on
      # - VPN_PORT_FORWARDING_PROVIDER=protonvpn
      - PORT_FORWARD_ONLY=on
      - "SERVER_COUNTRIES=${SERVER_COUNTRIES}"
      # - FREE_ONLY=off
      # DNS & stability
      - DOT=off
      - UPDATER_PERIOD=${UPDATER_PERIOD}
      - HEALTH_TARGET_ADDRESS=1.1.1.1:443
      # Control server (RBAC)
      - HTTP_CONTROL_SERVER_ADDRESS=:${GLUETUN_CONTROL_PORT}
      - HTTP_CONTROL_SERVER_LOG=off
      - HTTP_CONTROL_SERVER_AUTH_FILE=/gluetun/auth/config.toml
      - VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c 'wget -qO- --retry-connrefused --post-data "json={\"listen_port\":{{PORTS}},\"use_upnp\":false,\"use_natpmp\":false}" http://${GLUETUN_CONTROL_HOST}:${QBT_WEBUI_PORT}/api/v2/app/setPreferences'
      - PUID=${PUID}
      - PGID=${PGID}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
      - ${ARR_DOCKER_DIR}/gluetun/auth:/gluetun/auth
    ports:
      - "${LAN_IP}:${GLUETUN_CONTROL_PORT}:${GLUETUN_CONTROL_PORT}"          # Gluetun control API (LAN-only)
      - "${LAN_IP}:${QBT_HTTP_PORT_HOST}:${QBT_WEBUI_PORT}"   # qB WebUI via gluetun namespace
      - "${LAN_IP}:${SONARR_PORT}:${SONARR_PORT}"                    # Sonarr
      - "${LAN_IP}:${RADARR_PORT}:${RADARR_PORT}"                    # Radarr
      - "${LAN_IP}:${PROWLARR_PORT}:${PROWLARR_PORT}"                    # Prowlarr
      - "${LAN_IP}:${BAZARR_PORT}:${BAZARR_PORT}"                    # Bazarr
      - "${LAN_IP}:${FLARESOLVERR_PORT}:${FLARESOLVERR_PORT}"                    # FlareSolverr
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip >/dev/null && wget -qO- http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/${VPN_TYPE}/status | grep -q 'status.:.running'"]
      interval: 45s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    container_name: qbittorrent
    network_mode: "service:gluetun"
    environment:
      - WEBUI_PORT=${QBT_WEBUI_PORT}
      - DOCKER_MODS=ghcr.io/gabe565/linuxserver-mod-vuetorrent
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TIMEZONE}
      - QBT_USER=${QBT_USER}
      - QBT_PASS=${QBT_PASS}
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${QBT_WEBUI_PORT}/api/v2/app/version >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    restart: unless-stopped

  sonarr:
    image: ghcr.io/hotio/sonarr:release
    container_name: sonarr
    network_mode: "service:gluetun"
    environment:
      - PUID=${PUID}
      - PGID=${PGID}
      - TZ=${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${TV_DIR}:/tv
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      prowlarr:
        condition: service_healthy
      qbittorrent:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${SONARR_PORT} >/dev/null"]
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
      - TZ=${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${MOVIES_DIR}:/movies
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      prowlarr:
        condition: service_healthy
      qbittorrent:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${RADARR_PORT} >/dev/null"]
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
      - TZ=${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on:
      qbittorrent:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${PROWLARR_PORT} >/dev/null"]
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
      - TZ=${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
      - ${SUBS_DIR}:/subs
    depends_on:
      sonarr:
        condition: service_healthy
      radarr:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${BAZARR_PORT} >/dev/null"]
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
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${FLARESOLVERR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped
YAML
  } >"${ARR_STACK_DIR}/docker-compose.yml"
  ok "Wrote ${ARR_STACK_DIR}/docker-compose.yml"
}

# ------------------------------[ STARTUP ]-------------------------------------
validate_creds_or_die() {
  local VM ENVF="${ARR_STACK_DIR}/.env"
  VM="$(grep -E '^VPN_MODE=' "$ENVF" | cut -d= -f2- || echo openvpn)"
  if [[ "$VM" = openvpn ]]; then
    local PU PP
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
  fi
}
pull_images() {
  step "11/12 Pulling images"
  compose_cmd pull || warn "Pull failed; will rely on up"
}
start_with_checks() {
  step "12/12 Starting the stack with enhanced health monitoring"
  validate_creds_or_die
  local VM
  VM="$(grep -E '^VPN_MODE=' "${ARR_STACK_DIR}/.env" | cut -d= -f2- || echo "${DEFAULT_VPN_MODE}")"
  local MAX_RETRIES=5 RETRY=0
  while [[ $RETRY -lt $MAX_RETRIES ]]; do
    note "→ Attempt $((RETRY + 1))/${MAX_RETRIES}"
    compose_cmd up -d gluetun || warn "gluetun up failed"
    local waited=0 HEALTH="unknown" IP="" PF=""
    while [[ $waited -lt 180 ]]; do
      HEALTH="$(docker inspect gluetun --format='{{.State.Health.Status}}' 2>/dev/null || echo unknown)"
      IP="$(docker exec gluetun wget -qO- http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip 2>/dev/null || true)"
      if [[ "$VM" = openvpn ]]; then
        PF="$(docker exec gluetun wget -qO- http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded 2>/dev/null | grep -o '[0-9]\+' || true)"
        [[ "$HEALTH" = healthy && -n "$IP" && -n "$PF" && "$PF" -gt 1024 ]] && break
      else
        [[ "$HEALTH" = healthy && -n "$IP" ]] && break
      fi
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
  if [[ -z "${QBT_USER}" || -z "${QBT_PASS}" ]]; then
    sleep 5
    local qb_line
    qb_line="$(docker logs qbittorrent 2>&1 | grep -i password | tail -n 1 || true)"
    if [[ -n "$qb_line" ]]; then
      note "qBittorrent initial password: ${qb_line##* }"
    else
      warn "Could not determine qBittorrent password; check 'docker logs qbittorrent'"
    fi
  else
    ok "qBittorrent credentials preseeded"
  fi
  compose_cmd ps || true
  note "Public IP:"
  wget -qO- http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip || true
  if [[ "$VM" = openvpn ]]; then
    note "Forwarded port:"
    wget -qO- http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded || true
  fi
}

install_aliases() {
  step "Installing ARR helper aliases"
  local src
  src="$(dirname "${BASH_SOURCE[0]}")/.aliasarr"
  local dst="${ARR_STACK_DIR}/.aliasarr"
  run_cmd cp "$src" "$dst"
  local shellrc="/home/${USER_NAME}/.zshrc"
  local line="[ -f \"$dst\" ] && source \"$dst\""
  if ! grep -Fq "$line" "$shellrc" 2>/dev/null; then
    if is_dry; then
      note "[DRY] append ARR vars and source to $shellrc"
    else
      {
        printf '%s\n' "export ARR_BASE=\"$ARR_BASE\""
        printf '%s\n' "export ARR_STACK_DIR=\"$ARR_STACK_DIR\""
        printf '%s\n' "export ARR_DOCKER_DIR=\"$ARR_DOCKER_DIR\""
        printf '%s\n' "export ARR_BACKUP_DIR=\"$ARR_BACKUP_DIR\""
        printf '%s\n' "export ARR_ENV_FILE=\"$ARR_STACK_DIR/.env\""
        printf '%s\n' "export LAN_IP=\"$LAN_IP\""
        printf '%s\n' "$line"
      } >>"$shellrc"
    fi
    ok "ARR aliases added to $shellrc"
  else
    ok "ARR aliases already present in $shellrc"
  fi
}

# --------------------------------[ MAIN ]--------------------------------------
main() {
  parse_args "$@"
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
  warn_lan_ip
  write_gluetun_auth
  write_env
  seed_wireguard_from_conf
  preseed_qbt_config
  write_compose
  pull_images
  start_with_checks
  install_aliases
  echo
  ok "Done. Next steps:"
  echo "  • Edit ${PROTON_CREDS_FILE} (username WITHOUT +pmp) if you haven't already."
  echo "  • qB Web UI: http://<host>:${QBT_HTTP_PORT_HOST} (initial password shown above; set QBT_USER/QBT_PASS before first run to preseed)."
}

main "$@"
