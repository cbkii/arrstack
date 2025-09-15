#!/usr/bin/env bash
# =============================================================================
#  ARR+VPN STACK INSTALLER
# =============================================================================
set -euo pipefail

# Resolve repo root if not already set
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# 1) Load tracked defaults
if [ -f "${REPO_ROOT}/arrconf/userconf.defaults.sh" ]; then
  # shellcheck source=/dev/null
  . "${REPO_ROOT}/arrconf/userconf.defaults.sh"
fi

# 2) Load user overrides (untracked)
if [ -f "${REPO_ROOT}/arrconf/userconf.sh" ]; then
  # shellcheck source=/dev/null
  . "${REPO_ROOT}/arrconf/userconf.sh"
fi

# shellcheck source=/dev/null
[ -f "${REPO_ROOT}/arrconf/helpers.sh" ] && . "${REPO_ROOT}/arrconf/helpers.sh"

case "${1:-}" in
  conf-diff)
    arrconf_diff
    exit $?
    ;;
esac

# Critical host ports we may free up (recomputed after overrides)
CRITICAL_PORTS="${CRITICAL_PORTS:-${QBT_HTTP_PORT_HOST} ${SONARR_PORT} ${RADARR_PORT} ${PROWLARR_PORT} ${BAZARR_PORT} ${FLARESOLVERR_PORT} ${GLUETUN_CONTROL_PORT}}"

# Ensure env file path
ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"

# Export for compose templating
export ARR_BASE ARR_DOCKER_DIR ARR_STACK_DIR ARR_BACKUP_DIR ARR_ENV_FILE LEGACY_VPNCONFS_DIR ARRCONF_DIR
export MEDIA_DIR DOWNLOADS_DIR COMPLETED_DIR MOVIES_DIR TV_DIR SUBS_DIR
export QBT_WEBUI_PORT QBT_HTTP_PORT_HOST QBT_USER QBT_PASS QBT_SAVE_PATH QBT_TEMP_PATH LAN_IP GLUETUN_CONTROL_PORT GLUETUN_CONTROL_HOST GLUETUN_HEALTH_TARGET PUID PGID TIMEZONE
export SONARR_PORT RADARR_PORT PROWLARR_PORT BAZARR_PORT FLARESOLVERR_PORT
export DEFAULT_VPN_MODE SERVER_COUNTRIES SERVER_CC_PRIORITY DEFAULT_COUNTRY GLUETUN_API_KEY
# ----------------------------[ LOGGING ]---------------------------------------
if [[ "${NO_COLOR}" -eq 0 && -t 1 ]]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_RED='\033[31m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_BLUE='\033[36m'
else
  C_RESET=''
  C_BOLD=''
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
fi

ts() {
  local now diff
  now=$(date +%s)
  diff=$((now - SCRIPT_START))
  printf '%02d:%02d' $((diff / 60)) $((diff % 60))
}

out() {
  printf "%b\n" "$1" >>"${LOG_FILE}"
  printf "%b\n" "$1" >&3
}

step() { out "$(ts) ${C_BLUE}${C_BOLD}✴️ $1${C_RESET}"; }
note() { out "$(ts) ${C_BLUE}➤ $1${C_RESET}"; }
ok() { out "$(ts) ${C_GREEN}✔ $1${C_RESET}"; }
warn() { out "$(ts) ${C_YELLOW}⚠ $1${C_RESET}"; }
err() { out "$(ts) ${C_RED}✖ $1${C_RESET}"; }
die() {
  err "$1"
  exit 1
}

# shellcheck disable=SC2015
trace() { [ "$DEBUG" = "1" ] && printf "[trace] %s\n" "$1" >>"${LOG_FILE}" || true; }
is_dry() { [[ "$DRY_RUN" = "1" ]]; }

show_spinner() {
  local pid=$1 spin=$'|/-\\' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf '\r%s' "${spin:i++%4:1}" >&3
    sleep 0.1
  done
  printf '\r\033[K' >&3
}

run_cmd() {
  local spinner=0
  if [[ "${1:-}" = '--spinner' ]]; then
    spinner=1
    shift
  fi

  # Preserve arguments to avoid word splitting/globbing
  local -a cmd=("$@")
  if is_dry; then
    note "[DRY] $(printf '%q ' "${cmd[@]}")"
    return 0
  fi

  {
    printf '+ '
    printf '%q ' "${cmd[@]}"
    printf '\n'
  } >>"${LOG_FILE}"

  local status
  set +e
  if [[ $spinner -eq 1 ]]; then
    "${cmd[@]}" &
    local pid=$!
    show_spinner "$pid"
    wait "$pid"
    status=$?
  else
    "${cmd[@]}"
    status=$?
  fi
  set -e
  if [[ $status -ne 0 ]]; then
    warn "Command failed ($status): $(printf '%q ' "${cmd[@]}")"
  fi
  return $status
}

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
  step "1/15 Checking prerequisites"
  [[ "$(whoami)" == "${USER_NAME}" ]] || die "Run as '${USER_NAME}' (current: $(whoami))"

  local pkgs=()
  command -v docker >/dev/null 2>&1 || pkgs+=(docker.io)
  docker compose version >/dev/null 2>&1 || pkgs+=(docker-compose-plugin)
  command -v wget >/dev/null 2>&1 || pkgs+=(wget)
  command -v curl >/dev/null 2>&1 || pkgs+=(curl)
  command -v ss >/dev/null 2>&1 || pkgs+=(iproute2)
  command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
  command -v xxd >/dev/null 2>&1 || pkgs+=(xxd)
  if ((${#pkgs[@]})); then
    note "Installing packages: ${pkgs[*]}"
    run_cmd --spinner sudo apt-get update -y || true
    run_cmd --spinner sudo apt-get install -y "${pkgs[@]}" || true
  fi

  for b in docker wget curl ss openssl xxd; do
    command -v "$b" >/dev/null 2>&1 || die "Missing dependency: $b"
  done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 not available"
  ok "All prerequisites installed"
}

# ----------------------------[ CLEANUP PHASE ]---------------------------------
compose_cmd() {
  local run_opts=()
  if [[ ${1:-} == '--spinner' ]]; then
    run_opts+=(--spinner)
    shift
  fi
  run_cmd "${run_opts[@]}" docker compose --env-file "$ARR_ENV_FILE" -f "${ARR_STACK_DIR}/docker-compose.yml" "$@"
}

stop_stack_if_present() {
  step "2/15 Stopping any existing stack"
  if [[ -f "${ARR_STACK_DIR}/docker-compose.yml" && -f "${ARR_ENV_FILE}" ]]; then
    compose_cmd --spinner down || true
  else
    note "No existing stack to stop"
  fi
}
stop_named_containers() {
  note "Removing known containers"
  # shellcheck disable=SC2015
  for c in ${ALL_CONTAINERS}; do docker ps -a --format '{{.Names}}' | grep -q "^${c}$" && run_cmd docker rm -f "$c" || true; done
}
clear_port_conflicts() {
  note "Clearing port conflicts"
  for p in ${CRITICAL_PORTS}; do if sudo fuser "${p}/tcp" >/dev/null 2>&1; then
    warn "Killing process on :$p"
    run_cmd sudo fuser -k "${p}/tcp" || true
  fi; done
}
stop_native_services() {
  note "Stopping native services"
  for SVC in ${ALL_NATIVE_SERVICES}; do
    if systemctl list-units --all --type=service | grep -q "${SVC}.service"; then
      note "Stopping ${SVC}…"
      run_cmd sudo systemctl stop "${SVC}" || true
      run_cmd sudo systemctl disable "${SVC}" || true
      run_cmd sudo systemctl mask "${SVC}" || true
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
  step "3/15 Creating folders"
  ensure_dir "${ARR_STACK_DIR}"
  ensure_dir "${ARR_BACKUP_DIR}"
  for d in gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr; do ensure_dir "${ARR_DOCKER_DIR}/${d}"; done
  for d in "${MEDIA_DIR}" "${DOWNLOADS_DIR}" "${DOWNLOADS_DIR}/incomplete" "${COMPLETED_DIR}" "${MEDIA_DIR}" "${MOVIES_DIR}" "${TV_DIR}" "${SUBS_DIR}"; do ensure_dir "$d"; done
}
backup_configs() {
  step "4/15 Backing up ALL existing configurations"
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
  step "5/15 Moving native application directories"
  local NATIVE_MOVE_DIR="${BACKUP_SUBDIR}/native-configs"
  ensure_dir "${NATIVE_MOVE_DIR}"
  for D in ${NATIVE_DIRS}; do if [[ -d "$D" ]]; then
    run_cmd sudo mv "$D" "${NATIVE_MOVE_DIR}/$(basename "$D")" 2>/dev/null || true
    note "Moved $D -> ${NATIVE_MOVE_DIR}/$(basename "$D")"
  fi; done
}
purge_native_packages() {
  step "6/15 Purging ALL native packages"
  run_cmd --spinner sudo apt-get update -y || true
  for PKG in ${ALL_PACKAGES}; do if dpkg -l | grep -q "^ii.*${PKG}"; then
    note "Purging ${PKG}…"
    run_cmd sudo apt-get purge -y "${PKG}" || true
  fi; done
  run_cmd --spinner sudo apt-get autoremove -y || true
  ok "Native packages purged"
}
final_docker_cleanup() {
  step "7/15 Final Docker cleanup pass"
  for CONTAINER in ${ALL_CONTAINERS}; do
    if docker ps -aq --filter "name=${CONTAINER}" | grep -q .; then
      run_cmd docker rm -f "$(docker ps -aq --filter "name=${CONTAINER}")" || true
    else
      note "No leftover ${CONTAINER}"
    fi
  done
  ok "Docker containers cleaned"
}

# ---------------------------[ ARRCONF SECRETS ]--------------------------------
harden_arrconf() {
  ensure_dir "${ARRCONF_DIR}"
  local changed=0 perm
  perm=$(stat -c '%a' "${ARRCONF_DIR}" 2>/dev/null || echo "")
  if [[ "$perm" != "700" ]]; then
    run_cmd chmod 700 "${ARRCONF_DIR}" || run_cmd sudo chmod 700 "${ARRCONF_DIR}" || true
    changed=1
  fi
  shopt -s nullglob
  for f in "${ARRCONF_DIR}"/proton.auth "${ARRCONF_DIR}"/wg*.conf; do
    [[ -e "$f" ]] || continue
    perm=$(stat -c '%a' "$f" 2>/dev/null || echo "")
    if [[ "$perm" != "600" ]]; then
      run_cmd chmod 600 "$f" || run_cmd sudo chmod 600 "$f" || true
      changed=1
    fi
  done
  shopt -u nullglob
  if [[ $changed -eq 1 ]]; then
    warn "Tightened permissions in ${ARRCONF_DIR}"
  fi
}

ensure_proton_auth() {
  step "8/15 Ensuring Proton auth"
  harden_arrconf
  if [[ ! -f "${PROTON_AUTH_FILE}" ]]; then
    if [[ -f "${LEGACY_CREDS_WG}" ]]; then
      if run_cmd mv "${LEGACY_CREDS_WG}" "${PROTON_AUTH_FILE}"; then
        warn "Migrated legacy creds from ${LEGACY_CREDS_WG}"
      else
        warn "Failed to migrate creds from ${LEGACY_CREDS_WG}"
      fi
    elif [[ -f "${LEGACY_CREDS_DOCKER}" ]]; then
      if run_cmd mv "${LEGACY_CREDS_DOCKER}" "${PROTON_AUTH_FILE}"; then
        warn "Migrated legacy creds from ${LEGACY_CREDS_DOCKER}"
      else
        warn "Failed to migrate creds from ${LEGACY_CREDS_DOCKER}"
      fi
    else
      atomic_write "${PROTON_AUTH_FILE}" "# Proton account credentials (do NOT include +pmp)\nPROTON_USER=\nPROTON_PASS=\n"
      warn "Created template ${PROTON_AUTH_FILE}; edit with your Proton credentials"
    fi
  else
    ok "Found ${PROTON_AUTH_FILE}"
  fi
  run_cmd chmod 600 "${PROTON_AUTH_FILE}" || run_cmd sudo chmod 600 "${PROTON_AUTH_FILE}" || true
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
  local n="proton.conf" c files=()
  [ $# -gt 0 ] && n="$1"
  if [[ -d "${ARRCONF_DIR}" ]]; then
    if [[ -f "${ARRCONF_DIR}/${n}" ]]; then
      files=("${ARRCONF_DIR}/${n}")
    else
      shopt -s nullglob
      files=("${ARRCONF_DIR}"/wg*.conf)
      shopt -u nullglob
      if [[ ${#files[@]} -gt 1 ]]; then
        warn "Multiple WireGuard configs in ${ARRCONF_DIR}; using $(basename "${files[0]}")"
      fi
    fi
  fi
  if [[ ${#files[@]} -gt 0 ]]; then
    printf '%s\n' "${files[0]}"
    return 0
  fi
  for c in "${ARR_DOCKER_DIR}/gluetun/${n}" \
    "${ARR_DOCKER_DIR}/gluetun"/wg*.conf \
    "${LEGACY_VPNCONFS_DIR}"/wg*.conf \
    "${LEGACY_VPNCONFS_DIR}/${n}"; do
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
  step "9/15 Generating Gluetun API key"
  if [[ -f "${ARR_ENV_FILE}" ]]; then
    GLUETUN_API_KEY="$(grep -E '^GLUETUN_API_KEY=' "${ARR_ENV_FILE}" | cut -d= -f2- || true)"
  fi
  if [[ -z "${GLUETUN_API_KEY}" ]]; then
    if run_cmd --spinner docker run --rm ghcr.io/qdm12/gluetun genkey >/tmp/gl_apikey; then
      GLUETUN_API_KEY="$(cat /tmp/gl_apikey)"
    else
      run_cmd --spinner openssl rand -base64 48 >/tmp/gl_apikey
      GLUETUN_API_KEY="$(cat /tmp/gl_apikey)"
    fi
    rm -f /tmp/gl_apikey
    ok "API key generated"
  else
    ok "Reusing existing API key"
  fi
}
write_gluetun_auth() {
  step "10/15 Writing Gluetun RBAC config"
  local AUTH_DIR="${ARR_DOCKER_DIR}/gluetun/auth"
  ensure_dir "$AUTH_DIR"
  local toml='# Gluetun Control-Server RBAC config\n[[roles]]\nname="readonly"\nauth="basic"\nusername="gluetun"\npassword="'"${GLUETUN_API_KEY}"'\nroutes=["GET /v1/openvpn/status","GET /v1/wireguard/status","GET /v1/publicip/ip","GET /v1/openvpn/portforwarded"]\n'
  atomic_write "${AUTH_DIR}/config.toml" "$toml"
  run_cmd chmod 600 "${AUTH_DIR}/config.toml"
}

# ---------------------------[ PORT MONITOR ]-----------------------------------
# ------------------------------[ .ENV FILE ]-----------------------------------
write_env() {
  step "11/15 Writing stack .env"
  local envf="${ARR_ENV_FILE}"
  ensure_dir "${ARR_STACK_DIR}"
  local PU="" PP="" CN="${SERVER_COUNTRIES}"
  if [[ -f "${PROTON_AUTH_FILE}" ]]; then
    PU="$(grep -E '^PROTON_USER=' "${PROTON_AUTH_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(grep -E '^PROTON_PASS=' "${PROTON_AUTH_FILE}" | cut -d= -f2- | tr -d '"' || true)"
  fi
  local env_content
  env_content=$(
    cat <<EOF
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
ARRCONF_DIR=${ARRCONF_DIR}
MEDIA_DIR=${MEDIA_DIR}
DOWNLOADS_DIR=${DOWNLOADS_DIR}
COMPLETED_DIR=${COMPLETED_DIR}
MOVIES_DIR=${MOVIES_DIR}
TV_DIR=${TV_DIR}
SUBS_DIR=${SUBS_DIR}

# ProtonVPN config
VPN_MODE=${VPN_MODE}
VPN_TYPE=${VPN_MODE}
SERVER_COUNTRIES="${CN}"
SERVER_CC_PRIORITY="${SERVER_CC_PRIORITY}"
# UPDATER_PERIOD=24h
UPDATER_PERIOD=0
EOF
  )
  local proton_env="${ARRCONF_DIR}/proton.env"
  if [[ "${VPN_MODE}" = "openvpn" ]]; then
    [[ -n "${PU}" && -n "${PP}" ]] || die "Missing Proton credentials at ${PROTON_AUTH_FILE}"
    local OUSER
    OUSER="$(ensure_pmp "${PU}")"
    env_content+="
OPENVPN_USER=${OUSER}
OPENVPN_PASSWORD=${PP}"
    atomic_write "${proton_env}" "OPENVPN_USER=${OUSER}\nOPENVPN_PASSWORD=${PP}\n"
  else
    atomic_write "${proton_env}" "# Proton OpenVPN credentials (unused for WireGuard)\n"
    env_content+="
WIREGUARD_MTU=1320"
  fi
  atomic_write "${envf}" "${env_content}\n"
  run_cmd chmod 600 "${proton_env}"
  run_cmd chmod 600 "${envf}"
  ok "Wrote ${envf}"
}

# Warn if LAN_IP is 0.0.0.0 which exposes services on all interfaces
warn_lan_ip() {
  if [ "${LAN_IP}" = "0.0.0.0" ]; then
    warn "LAN_IP is set to 0.0.0.0 — this would expose the Gluetun API publicly. Set LAN_IP to your LAN interface IP (e.g. 192.168.1.10) for LAN-only access."
  fi
}

# Populate WireGuard variables from a Proton .conf and fail if malformed when VPN_MODE=wireguard
seed_wireguard_from_conf() {
  local VM CONF K A D
  VM="$(grep -E '^VPN_MODE=' "${ARR_ENV_FILE}" | cut -d= -f2- || echo "${DEFAULT_VPN_MODE}")"
  if [[ "$VM" = "wireguard" ]]; then
    CONF="$(find_wg_conf "proton.conf" 2>/dev/null)" || die "VPN_MODE=wireguard but no WireGuard .conf found in ${ARRCONF_DIR}, ${ARR_DOCKER_DIR}/gluetun or ${LEGACY_VPNCONFS_DIR}"
    read -r K A D < <(parse_wg_conf "$CONF" 2>/dev/null) || die "Malformed WireGuard config: $CONF"
    sed -i '/^WIREGUARD_PRIVATE_KEY=/d;/^WIREGUARD_ADDRESSES=/d;/^VPN_DNS_ADDRESS=/d' "${ARR_ENV_FILE}"
    echo "WIREGUARD_PRIVATE_KEY=${K}" >>"${ARR_ENV_FILE}"
    [ -n "$A" ] && echo "WIREGUARD_ADDRESSES=${A}" >>"${ARR_ENV_FILE}"
    [ -n "$D" ] && echo "VPN_DNS_ADDRESS=${D}" >>"${ARR_ENV_FILE}"
    ok "Seeded WG from $(basename "$CONF")"
  fi
}

ensure_qbt_conf() {
  local conf_dir="${ARR_DOCKER_DIR}/qbittorrent"
  local conf="${conf_dir}/qBittorrent.conf"
  install -d -m 0750 -o "${PUID}" -g "${PGID}" "${conf_dir}"
  if [ ! -f "${conf}" ]; then
    cat >"${conf}" <<CONFEOF
[Preferences]
# --- WebUI security & LAN behaviour ---
WebUI\\BypassLocalAuth=true
WebUI\\CSRFProtection=true
WebUI\\ClickjackingProtection=true
WebUI\\HostHeaderValidation=true
WebUI\\HTTPS\\Enabled=false
WebUI\\Address=*
WebUI\\ServerDomains=*
WebUI\\Port=${QBT_WEBUI_PORT}

# --- Avoid conflicts with Proton NAT-PMP (let Gluetun set the listen port) ---
Connection\\UPnP=false
Connection\\UseUPnP=false
Connection\\UseNAT-PMP=false

# --- Paths inside the container ---
Downloads\\SavePath=${QBT_SAVE_PATH}
Downloads\\TempPath=${QBT_TEMP_PATH}
Downloads\\TempPathEnabled=true
CONFEOF
    chown "${PUID}:${PGID}" "${conf}"
    chmod 0640 "${conf}"
  fi
}

need() { command -v "$1" >/dev/null 2>&1 || {
  echo "Missing dependency: $1" >&2
  return 1
}; }

check_hash_deps() {
  need openssl && need base64 && need sed && need awk && need grep || return 1
  if ! openssl version | grep -qE 'OpenSSL 3\.'; then
    echo "OpenSSL 3 required (found: $(openssl version))" >&2
    return 1
  fi
  if ! openssl kdf -help >/dev/null 2>&1; then
    echo "'openssl kdf' subcommand not available; need OpenSSL 3" >&2
    return 1
  fi
}

# Inputs: QBT_USER, QBT_PASS
# Outputs: SALT_B64, DK_B64
derive_qbt_hash() {
  : "${QBT_USER:?QBT_USER not set}" "${QBT_PASS:?QBT_PASS not set}"
  local salt_hex dk_b64 salt_b64
  salt_hex="$(openssl rand -hex 16)"
  dk_b64="$(openssl kdf -binary -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt pass:"${QBT_PASS}" \
    -kdfopt hexsalt:"${salt_hex}" \
    -kdfopt iter:100000 \
    PBKDF2 | base64 | tr -d '\n')"
  if command -v xxd >/dev/null 2>&1; then
    salt_b64="$(printf '%s' "${salt_hex}" | xxd -r -p | base64 | tr -d '\n')"
  else
    salt_b64="$(printf "%b" "$(printf '%s' "${salt_hex}" | sed 's/../\\x&/g')" | base64 | tr -d '\n')"
  fi
  export SALT_B64="${salt_b64}" DK_B64="${dk_b64}"
}

write_qbt_conf_hash() {
  local dir="${ARR_DOCKER_DIR}/qbittorrent"
  local cfg="${dir}/qBittorrent.conf"
  install -d -m 0750 -o "${PUID}" -g "${PGID}" "${dir}"
  if [ ! -f "${cfg}" ]; then
    cat >"${cfg}" <<'CONFEOF'
[Preferences]
WebUI\BypassLocalAuth=true
WebUI\CSRFProtection=true
WebUI\ClickjackingProtection=true
WebUI\HostHeaderValidation=true
WebUI\HTTPS\Enabled=false
WebUI\Address=*
WebUI\ServerDomains=*
WebUI\Port=${QBT_WEBUI_PORT}
Connection\UPnP=false
Connection\UseUPnP=false
Connection\UseNAT-PMP=false
Downloads\SavePath=${QBT_SAVE_PATH}
Downloads\TempPath=${QBT_TEMP_PATH}
Downloads\TempPathEnabled=true
CONFEOF
  fi

  grep -q '^\[Preferences\]' "${cfg}" || printf '\n[Preferences]\n' >>"${cfg}"

  if grep -q '^WebUI\\Username=' "${cfg}"; then
    sed -i.bak "s#^WebUI\\Username=.*#WebUI\\Username=${QBT_USER}#g" "${cfg}"
  else
    printf 'WebUI\\Username=%s\n' "${QBT_USER}" >>"${cfg}"
  fi

  local pb_line="WebUI\\Password_PBKDF2=\"@ByteArray(${SALT_B64}:${DK_B64})\""
  if grep -q '^WebUI\\Password_PBKDF2=' "${cfg}"; then
    sed -i.bak "s#^WebUI\\Password_PBKDF2=.*#${pb_line//#/\\#}#g" "${cfg}"
  else
    printf '%s\n' "${pb_line}" >>"${cfg}"
  fi

  chown "${PUID}:${PGID}" "${cfg}"
  chmod 0640 "${cfg}"
  rm -f "${cfg}.bak" 2>/dev/null || true
}

seed_qbt_credentials_if_requested() {
  if [ -n "${QBT_USER:-}" ] && [ -n "${QBT_PASS:-}" ]; then
    if check_hash_deps; then
      derive_qbt_hash
      write_qbt_conf_hash
      echo "qBittorrent WebUI creds pre-seeded for user '${QBT_USER}' (password hashed)."
    else
      echo "Warning: hashing deps missing; will not pre-seed qB credentials. A temporary password will be generated on first start."
      QBT_USER=""
      QBT_PASS=""
    fi
  else
    echo "No QBT_USER/QBT_PASS provided; will use LSIO temporary password flow."
  fi
}

print_qbt_temp_password_if_any() {
  if [ -z "${QBT_USER:-}" ] || [ -z "${QBT_PASS:-}" ]; then
    sleep 3
    local tmp_pw
    tmp_pw="$(docker logs --tail=300 qbittorrent 2>&1 | sed -nE 's/.*temporary password is[: ]+([A-Za-z0-9]+).*/\1/p' | head -n1 || true)"
    if [ -n "${tmp_pw}" ]; then
      echo "qBittorrent WebUI → http://${LAN_IP}:${QBT_HTTP_PORT_HOST}"
      echo "Login: admin / ${tmp_pw}"
      echo "IMPORTANT: Change this password in qB → Web UI settings."
    fi
  fi
}

# ---------------------------[ COMPOSE FILE ]-----------------------------------
write_compose() {
  step "12/15 Writing docker-compose.yml"
  {
    cat <<'YAML'
services:
  gluetun:
    image: qmcgaw/gluetun:v3.38.0
    container_name: gluetun
    cap_add: ["NET_ADMIN"]
    devices:
      - /dev/net/tun:/dev/net/tun
    env_file:
      - ${ARRCONF_DIR}/proton.env
    environment:
      - TZ=${TIMEZONE}
      - VPN_SERVICE_PROVIDER=protonvpn
      - VPN_TYPE=${VPN_TYPE}
YAML
    if [ "${VPN_MODE}" = "wireguard" ]; then
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
      - SERVER_COUNTRIES="${SERVER_COUNTRIES}"
      # - FREE_ONLY=off
      # DNS & stability
      - DOT=off
      - UPDATER_PERIOD=${UPDATER_PERIOD}
      - HEALTH_TARGET_ADDRESS=${GLUETUN_HEALTH_TARGET}
      - HEALTH_VPN_DURATION_INITIAL=30s
      - HEALTH_SUCCESS_WAIT_DURATION=10s
      # Control server (RBAC)
      - HTTP_CONTROL_SERVER_ADDRESS="${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}"
      - HTTP_CONTROL_SERVER_LOG=off
      - HTTP_CONTROL_SERVER_AUTH_FILE=/gluetun/auth/config.toml
      - VPN_PORT_FORWARDING_UP_COMMAND=/bin/sh -c '\
          for i in $(seq 1 30); do \
            wget -qO- --timeout=2 http://${GLUETUN_CONTROL_HOST}:${QBT_HTTP_PORT_HOST}/api/v2/app/version && break || sleep 1; \
          done; \
          wget -qO- --timeout=5 \
            --referer="http://${GLUETUN_CONTROL_HOST}:${QBT_HTTP_PORT_HOST}/" \
            --post-data "json={\"listen_port\":{{PORTS}},\"use_upnp\":false,\"use_natpmp\":false}" \
            http://${GLUETUN_CONTROL_HOST}:${QBT_HTTP_PORT_HOST}/api/v2/app/setPreferences >/dev/null 2>&1 || exit 0'
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
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://${GLUETUN_CONTROL_HOST}:${QBT_HTTP_PORT_HOST}/api/v2/app/version >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    restart: unless-stopped

  sonarr:
    image: lscr.io/linuxserver/sonarr:latest
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
    image: lscr.io/linuxserver/radarr:latest
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
  local VM ENVF="${ARR_ENV_FILE}"
  VM="$(grep -E '^VPN_MODE=' "$ENVF" | cut -d= -f2- || echo openvpn)"
  if [[ "$VM" = openvpn ]]; then
    local OU OP
    OU="$(grep -E '^OPENVPN_USER=' "$ENVF" | cut -d= -f2- || true)"
    OP="$(grep -E '^OPENVPN_PASSWORD=' "$ENVF" | cut -d= -f2- || true)"
    if [[ -z "${OU}" || -z "${OP}" ]]; then
      err "Proton credentials missing. Edit ${PROTON_AUTH_FILE} then re-run."
      exit 2
    fi
    if [[ "$OU" != *+pmp ]]; then
      warn "Fixing OPENVPN_USER to include +pmp"
      sed -i '/^OPENVPN_USER=/d' "$ENVF"
      printf 'OPENVPN_USER=%s\n' "$(ensure_pmp "$OU")" >>"$ENVF"
      if [[ -f "${ARRCONF_DIR}/proton.env" ]]; then
        sed -i '/^OPENVPN_USER=/d' "${ARRCONF_DIR}/proton.env"
        printf 'OPENVPN_USER=%s\n' "$(ensure_pmp "$OU")" >>"${ARRCONF_DIR}/proton.env"
      fi
    fi
  fi
}
pull_images() {
  step "13/15 Pulling images"
  if ! compose_cmd --spinner pull; then
    warn "Pull failed; will rely on up"
  fi
}
start_with_checks() {
  step "14/15 Starting the stack with enhanced health monitoring"
  validate_creds_or_die
  local VM
  VM="$(grep -E '^VPN_MODE=' "${ARR_ENV_FILE}" | cut -d= -f2- || echo "${DEFAULT_VPN_MODE}")"
  local MAX_RETRIES=5 RETRY=0
  while [[ $RETRY -lt $MAX_RETRIES ]]; do
    note "→ Attempt $((RETRY + 1))/${MAX_RETRIES}"
    compose_cmd up -d gluetun || warn "gluetun up failed"
    local waited=0 HEALTH="unknown" IP="" PF=""
    while [[ $waited -lt 180 ]]; do
      HEALTH="$(docker inspect gluetun --format='{{.State.Health.Status}}' 2>/dev/null || echo unknown)"
      IP="$(docker exec gluetun wget -qO- "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" 2>/dev/null || true)"
      if [[ "$VM" = openvpn ]]; then
        PF="$(docker exec gluetun wget -qO- "http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded" 2>/dev/null | grep -o '[0-9]\+' || true)"
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
  print_qbt_temp_password_if_any
  if [ -n "${QBT_USER:-}" ] && [ -n "${QBT_PASS:-}" ]; then
    ok "qBittorrent credentials preseeded"
  fi
  compose_cmd ps || true
  local ip pf
  ip="$(wget -qO- "http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" || true)"
  note "Public IP: ${ip}"
  if [[ "$VM" = openvpn ]]; then
    pf="$(wget -qO- "http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded" || true)"
    note "Forwarded port: ${pf}"
  fi
}

install_aliases() {
  step "15/15 Installing ARR helper aliases"
  local src
  src="$(dirname "${BASH_SOURCE[0]}")/.aliasarr"
  local dst="${ARR_STACK_DIR}/.aliasarr"
  run_cmd cp "$src" "$dst" || warn "Failed to copy alias file"
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
        printf '%s\n' "export ARR_ENV_FILE=\"$ARR_ENV_FILE\""
        printf '%s\n' "export ARRCONF_DIR=\"$ARRCONF_DIR\""
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
  SCRIPT_START=$(date +%s)
  step "0/15 ARR+VPN merged installer"
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
  ensure_proton_auth
  make_gluetun_apikey
  warn_lan_ip
  write_gluetun_auth
  write_env
  seed_wireguard_from_conf
  ensure_qbt_conf
  seed_qbt_credentials_if_requested
  write_compose
  pull_images
  start_with_checks
  install_aliases
  echo >&3
  ok "Done. Next steps:"
  note "  • Edit ${PROTON_AUTH_FILE} (username WITHOUT +pmp) if you haven't already."
  note "  • qB Web UI: http://<host>:${QBT_HTTP_PORT_HOST} (use printed admin password or preset QBT_USER/QBT_PASS)."
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  LOG_FILE="${ARR_STACK_DIR}/arrstack-install.log"
  mkdir -p "${ARR_STACK_DIR}"
  exec 3>&1 4>&2
  exec 1>>"${LOG_FILE}" 2>&1
  cleanup() {
    local status=$?
    exec 1>&3 2>&4
    echo "Log saved to ${LOG_FILE}" >&3
    exit "$status"
  }
  trap cleanup EXIT

  main "$@"
fi
