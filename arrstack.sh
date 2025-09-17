#!/usr/bin/env bash
# =============================================================================
#  ARR+VPN STACK INSTALLER
# =============================================================================
set -Euo pipefail
IFS=$'\n\t'

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

LOG_FILE=${LOG_FILE:-/dev/null}
if [[ "${NO_COLOR:-0}" -eq 0 && -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_GREEN=$'\033[32m'
  C_BLUE=$'\033[36m'
  C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m'
else
  C_RESET=''
  C_BOLD=''
  C_GREEN=''
  C_BLUE=''
  C_YELLOW=''
  C_RED=''
fi

warn() { printf '%b\n' "${C_YELLOW}⚠ $1${C_RESET}" >&2; }
die() {
  printf '%b\n' "${C_RED}✖ $1${C_RESET}" >&2
  exit 1
}

is_dry() { [[ "${DRY_RUN:-0}" == 1 ]]; }

_stringify_cmd() {
  local -a argv=("$@")
  local cmd=""
  for a in "${argv[@]}"; do
    cmd+=" $(printf '%q' "$a")"
  done
  printf '%s' "${cmd# }"
}

_redact() {
  sed -E \
    -e 's/(GLUETUN_API_KEY=)[^ ]+/\1<REDACTED>/g' \
    -e 's/(OPENVPN_PASSWORD=)[^ ]+/\1<REDACTED>/g' \
    -e 's/(OPENVPN_USER=)[^ ]+/\1<REDACTED>/g' \
    -e 's/(PROTON_PASS=)[^ ]+/\1<REDACTED>/g' \
    -e 's/(PROTON_USER=)[^ ]+/\1<REDACTED>/g'
}

_log_cmd() {
  local -a argv=("$@")
  printf '+ %s\n' "$(_stringify_cmd "${argv[@]}")" | _redact >>"$LOG_FILE"
}

_exec_cmd() {
  local warn_on_fail=$1
  shift || true
  local -a argv=("$@")
  _log_cmd "${argv[@]}"
  if is_dry; then
    return 0
  fi

  local rc
  if [[ "${argv[0]}" == docker && -e /dev/fd/3 ]]; then
    "${argv[@]}" 2>&1 | tee /dev/fd/3
    rc=${PIPESTATUS[0]}
  else
    "${argv[@]}"
    rc=$?
  fi

  if (( warn_on_fail )) && (( rc != 0 )); then
    warn "Command failed ($rc): $(_stringify_cmd "${argv[@]}")"
  fi
  return "$rc"
}

run() { _exec_cmd 0 "$@"; }

run_or_warn() { _exec_cmd 1 "$@"; }

require_env() {
  local var=$1
  [[ -n "${!var:-}" ]] || die "Missing env var: ${var}"
}

arrconf_diff() {
  local def="${REPO_ROOT}/arrconf/userconf.defaults.sh"
  local usr="${REPO_ROOT}/arrconf/userconf.sh"
  if [ ! -f "${def}" ]; then
    echo "Defaults not found at ${def}" >&2
    return 1
  fi
  if [ ! -f "${usr}" ]; then
    echo "No userconf.sh yet. Creating from defaults..."
    cp "${def}" "${usr}"
    echo "Edit ${usr} to override defaults."
    return 0
  fi
  echo "Comparing your overrides to new defaults:"
  diff -u "${def}" "${usr}" || true
}

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
export QBT_WEBUI_PORT QBT_HTTP_PORT_HOST QBT_USER QBT_PASS QBT_SAVE_PATH QBT_TEMP_PATH LAN_IP LOCALHOST_ADDR LOCALHOST_NAME GLUETUN_CONTROL_PORT GLUETUN_CONTROL_HOST GLUETUN_HEALTH_TARGET PUID PGID TIMEZONE UPDATER_PERIOD
export SONARR_PORT RADARR_PORT PROWLARR_PORT BAZARR_PORT FLARESOLVERR_PORT
export DEFAULT_VPN_TYPE SERVER_COUNTRIES DEFAULT_COUNTRY GLUETUN_API_KEY
# ----------------------------[ LOGGING ]---------------------------------------
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

# shellcheck disable=SC2015
trace() { [ "$DEBUG" = "1" ] && printf "[trace] %s\n" "$1" >>"${LOG_FILE}" || true; }

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --openvpn)
        VPN_TYPE="openvpn"
        ;;
      --wireguard)
        VPN_TYPE="wireguard"
        ;;
      -y|--yes)
        ASSUME_YES=1
        export ASSUME_YES
        ;;
    esac
    shift
  done
}

hydrate_vpn_type_from_env() {
  local envf="${ARR_ENV_FILE}"
  if [[ -f "$envf" ]] && grep -q '^VPN_MODE=' "$envf"; then
    local legacy
    legacy="$(grep -E '^VPN_MODE=' "$envf" | tail -n1 | cut -d= -f2-)"
    if [[ -n "${legacy}" ]]; then
      warn "Deprecated VPN_MODE detected in ${envf}; using VPN_TYPE=${legacy}"
      VPN_TYPE="${legacy}"
      export VPN_TYPE
    fi
  fi
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

have_ip() {
  local needle="$1"
  [[ -n "${needle}" ]] || return 1
  ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$needle"
}

ensure_lan_ip_binding() {
  if [[ -z "${LAN_IP:-}" ]]; then
    LAN_IP="0.0.0.0"
    export LAN_IP
    return
  fi
  if [[ "${LAN_IP}" = "0.0.0.0" ]] || have_ip "${LAN_IP}"; then
    export LAN_IP
    return
  fi
  warn "LAN_IP=${LAN_IP} not found on host; falling back to 0.0.0.0"
  LAN_IP="0.0.0.0"
  export LAN_IP
}

lan_access_host() {
  local host="${LAN_IP:-}"
  if [[ -z "$host" || "$host" = "0.0.0.0" ]]; then
    printf '%s' "${LOCALHOST_ADDR:-127.0.0.1}"
  else
    printf '%s' "$host"
  fi
}

# ----------------------------[ PREFLIGHT ]-------------------------------------
confirm_or_die() {
  if [ "${ASSUME_YES:-0}" = "1" ]; then
    return 0
  fi
  printf 'Proceed with installation? [y/N]: ' >&3
  read -r ans
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) die "Aborted by user" ;;
  esac
}

preflight() {
  step "0a/15 Preflight checks"
  hydrate_vpn_type_from_env
  if [[ -z "${VPN_TYPE:-}" ]]; then
    VPN_TYPE="${DEFAULT_VPN_TYPE}"
    export VPN_TYPE
  fi
  ensure_proton_auth_core
  PREFLIGHT_ENSURED_PROTON_AUTH=1
  ensure_lan_ip_binding
  warn_lan_ip

  local resolved="${VPN_TYPE}" fallback_used=0
  while :; do
    case "${resolved}" in
      openvpn)
        if ! grep -Eq '^PROTON_USER=[^#[:space:]].*' "${PROTON_AUTH_FILE}" 2>/dev/null \
           || ! grep -Eq '^PROTON_PASS=[^#[:space:]].*' "${PROTON_AUTH_FILE}" 2>/dev/null; then
          die "VPN_TYPE=openvpn but PROTON_USER/PROTON_PASS not set in ${PROTON_AUTH_FILE}. Edit it (username WITHOUT +pmp) and re-run."
        fi
        break
        ;;
      wireguard)
        if ! find_wg_conf "proton.conf" >/dev/null 2>&1; then
          die "VPN_TYPE=wireguard but proton.conf not found in ${ARRCONF_DIR}, ${ARR_DOCKER_DIR}/gluetun or ${LEGACY_VPNCONFS_DIR}."
        fi
        break
        ;;
      *)
        if (( fallback_used )); then
          die "Unsupported VPN_TYPE value '${resolved}'. Check your configuration."
        fi
        warn "Unknown VPN_TYPE='${resolved}'. Falling back to DEFAULT_VPN_TYPE='${DEFAULT_VPN_TYPE}'."
        resolved="${DEFAULT_VPN_TYPE}"
        VPN_TYPE="${resolved}"
        export VPN_TYPE
        fallback_used=1
        ;;
    esac
  done

  note "Summary:"
  note "  • VPN_TYPE=${VPN_TYPE}"
  note "  • LAN_IP=${LAN_IP}   Control: ${GLUETUN_CONTROL_HOST:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}"
  note "  • WebUI host port (qB): ${QBT_HTTP_PORT_HOST}  internal: ${QBT_WEBUI_PORT}"
  confirm_or_die
}

# ----------------------------[ PRECHECKS ]-------------------------------------
check_deps() {
  step "1/15 Checking prerequisites"
  [[ "$(whoami)" == "${USER_NAME}" ]] || die "Run as '${USER_NAME}' (current: $(whoami))"

  local pkgs=()
  command -v docker >/dev/null 2>&1 || pkgs+=(docker.io)
  docker compose version >/dev/null 2>&1 || pkgs+=(docker-compose-plugin)
  command -v curl >/dev/null 2>&1 || pkgs+=(curl)
  command -v ss >/dev/null 2>&1 || pkgs+=(iproute2)
  command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
  command -v xxd >/dev/null 2>&1 || pkgs+=(xxd)
  if ((${#pkgs[@]})); then
    note "Installing packages: ${pkgs[*]}"
    run_or_warn sudo apt-get update -y
    run_or_warn sudo apt-get install -y "${pkgs[@]}"
  fi

  for b in docker curl ss openssl xxd; do
    command -v "$b" >/dev/null 2>&1 || die "Missing dependency: $b"
  done
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 not available"
  ok "All prerequisites installed"
}

# ----------------------------[ CLEANUP PHASE ]---------------------------------
compose_cmd() {
  run docker compose --project-name arrstack --env-file "$ARR_ENV_FILE" -f "${ARR_STACK_DIR}/docker-compose.yml" "$@"
}

docker_rm_if_exists() {
  local token=$1
  local -a raw_ids=() exact_ids=() fallback_ids=() to_remove=()
  if ! mapfile -t raw_ids < <(docker ps -aq --filter "name=${token}"); then
    return 2
  fi
  if (( ${#raw_ids[@]} == 0 )); then
    return 1
  fi

  local id cname
  for id in "${raw_ids[@]}"; do
    [[ -n "$id" ]] || continue
    cname=$(docker inspect --format '{{.Name}}' "$id" 2>/dev/null || true)
    [[ -n "$cname" ]] || continue
    cname=${cname#/}
    if [[ "$cname" == "$token" ]]; then
      exact_ids+=("$id")
      continue
    fi
    if [[ "$cname" == *"-${token}"* || "$cname" == *"_${token}"* ]]; then
      fallback_ids+=("$id")
    fi
  done

  if (( ${#exact_ids[@]} )); then
    to_remove=("${exact_ids[@]}")
  elif (( ${#fallback_ids[@]} == 1 )); then
    to_remove=("${fallback_ids[@]}")
  elif (( ${#fallback_ids[@]} > 1 )); then
    warn "Multiple containers match token '${token}'; skipping fallback removal"
    return 4
  else
    return 1
  fi

  for id in "${to_remove[@]}"; do
    [[ -n "$id" ]] || continue
    run_or_warn docker rm -f "$id" || return $?
  done
  return 0
}

stop_stack_if_present() {
  step "2/15 Stopping any existing stack"
  if [[ -f "${ARR_STACK_DIR}/docker-compose.yml" && -f "${ARR_ENV_FILE}" ]]; then
    run_or_warn compose_cmd down
  else
    note "No existing stack to stop"
  fi
}
stop_named_containers() {
  note "Removing known containers"
  local removed_any=0 rc
  for c in ${ALL_CONTAINERS}; do
    docker_rm_if_exists "$c"
    rc=$?
    case $rc in
      0) removed_any=1 ;;
      1) ;; # no container with this name
      *) return $rc ;;
    esac
  done
  (( removed_any )) || note "No known containers present"
}
clear_port_conflicts() {
  note "Clearing port conflicts"
  for p in ${CRITICAL_PORTS}; do if sudo fuser "${p}/tcp" >/dev/null 2>&1; then
    warn "Killing process on :$p"
    run_or_warn sudo fuser -k "${p}/tcp"
  fi; done
}
stop_native_services() {
  note "Stopping native services"
  for SVC in ${ALL_NATIVE_SERVICES}; do
    if systemctl list-units --all --type=service | grep -q "${SVC}.service"; then
      note "Stopping ${SVC}…"
      run_or_warn sudo systemctl stop "${SVC}"
      run_or_warn sudo systemctl disable "${SVC}"
      run_or_warn sudo systemctl mask "${SVC}"
    fi
  done
  run_or_warn sudo systemctl daemon-reload
}
fix_permissions_on_base() {
  note "Fixing permissions under ${ARR_BASE}"
  if [[ -d "${ARR_BASE}" ]]; then
    note "Removing root-owned Docker artefacts (logs/pids/locks/servers.json)"
    run_or_warn sudo find "${ARR_BASE}" -name "servers.json" -exec rm -f {} \; 2>/dev/null
    run_or_warn sudo find "${ARR_BASE}" -name "*.log" -path "*/gluetun/*" -exec rm -f {} \; 2>/dev/null
    run_or_warn sudo find "${ARR_BASE}" -name "*.pid" -exec rm -f {} \; 2>/dev/null
    run_or_warn sudo find "${ARR_BASE}" -name "*.lock" -exec rm -f {} \; 2>/dev/null
    note "chown -R ${USER_NAME}:${USER_NAME} ${ARR_BASE}"
    run_or_warn sudo chown -R "${USER_NAME}:${USER_NAME}" "${ARR_BASE}" 2>/dev/null
    note "Standardising directory/file permissions"
    run_or_warn find "${ARR_BASE}" -type d -exec chmod 755 {} \; 2>/dev/null
    run_or_warn find "${ARR_BASE}" -type f -exec chmod 644 {} \; 2>/dev/null
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
  for d in "${MEDIA_DIR}" "${DOWNLOADS_DIR}" "${DOWNLOADS_DIR}/incomplete" "${COMPLETED_DIR}" "${MOVIES_DIR}" "${TV_DIR}" "${SUBS_DIR}"; do ensure_dir "$d"; done
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
      run_or_warn tar -C "${ARR_DOCKER_DIR}" -czf "${BACKUP_SUBDIR}/docker-${APP}-config.tgz" "${APP}" 2>/dev/null
      note "Saved ${BACKUP_SUBDIR}/docker-${APP}-config.tgz"
    fi
  done
  # Home configs
  for APP in qBittorrent Sonarr Radarr Prowlarr Bazarr Jackett Lidarr Readarr transmission; do
    if [[ -d "${HOME}/.config/${APP}" ]]; then
      run_or_warn tar -C "${HOME}/.config" -czf "${BACKUP_SUBDIR}/home-${APP}-config.tgz" "${APP}" 2>/dev/null
      note "Saved ${BACKUP_SUBDIR}/home-${APP}-config.tgz"
    fi
  done
  # System configs
  NATIVE_DIRS="/var/lib/sonarr /var/lib/radarr /var/lib/prowlarr /var/lib/bazarr /var/lib/jackett /var/lib/lidarr /var/lib/readarr \
/opt/Sonarr /opt/Radarr /opt/Prowlarr /opt/Bazarr /opt/Jackett /opt/Lidarr /opt/Readarr \
/etc/transmission-daemon"
  for D in ${NATIVE_DIRS}; do if [[ -d "$D" ]]; then
    APP_NAME="$(basename "$D")"
    run_or_warn sudo tar -czf "${BACKUP_SUBDIR}/system-${APP_NAME}.tgz" "$D" 2>/dev/null
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
    run_or_warn sudo mv "$D" "${NATIVE_MOVE_DIR}/$(basename "$D")" 2>/dev/null
    note "Moved $D -> ${NATIVE_MOVE_DIR}/$(basename "$D")"
  fi; done
}
purge_native_packages() {
  step "6/15 Purging ALL native packages"
  run_or_warn sudo apt-get update -y
  for PKG in ${ALL_PACKAGES}; do if dpkg -l | grep -q "^ii.*${PKG}"; then
    note "Purging ${PKG}…"
    run_or_warn sudo apt-get purge -y "${PKG}"
  fi; done
  run_or_warn sudo apt-get autoremove -y
  ok "Native packages purged"
}
final_docker_cleanup() {
  step "7/15 Final Docker cleanup pass"
  local overall=0 rc
  for CONTAINER in ${ALL_CONTAINERS}; do
    docker_rm_if_exists "$CONTAINER"
    rc=$?
    case $rc in
      0) ;;
      1) note "No leftover ${CONTAINER}" ;;
      *) overall=$rc ;;
    esac
  done
  if (( overall == 0 )); then
    ok "Docker containers cleaned"
  else
    warn "Docker cleanup encountered issues"
  fi
  return $overall
}

# ---------------------------[ ARRCONF SECRETS ]--------------------------------
harden_arrconf() {
  ensure_dir "${ARRCONF_DIR}"
  local changed=0 perm
  perm=$(stat -c '%a' "${ARRCONF_DIR}" 2>/dev/null || echo "")
  if [[ "$perm" != "700" ]]; then
    run chmod 700 "${ARRCONF_DIR}" || run_or_warn sudo chmod 700 "${ARRCONF_DIR}"
    changed=1
  fi
  shopt -s nullglob
  for f in "${ARRCONF_DIR}"/proton.auth "${ARRCONF_DIR}"/wg*.conf; do
    [[ -e "$f" ]] || continue
    perm=$(stat -c '%a' "$f" 2>/dev/null || echo "")
    if [[ "$perm" != "600" ]]; then
      run chmod 600 "$f" || run_or_warn sudo chmod 600 "$f"
      changed=1
    fi
  done
  shopt -u nullglob
  if [[ $changed -eq 1 ]]; then
    warn "Tightened permissions in ${ARRCONF_DIR}"
  fi
}

migrate_legacy_creds() {
  local src=$1 label=${2:-$1}
  [[ -f "$src" ]] || return 1
  if run mv "$src" "${PROTON_AUTH_FILE}"; then
    warn "Migrated legacy creds from ${label}"
    return 0
  fi
  warn "Failed to migrate creds from ${label}"
  return 2
}

ensure_proton_auth_core() {
  harden_arrconf
  if [[ ! -f "${PROTON_AUTH_FILE}" ]]; then
    local migrated=0 rc
    migrate_legacy_creds "${LEGACY_CREDS_WG}" "${LEGACY_CREDS_WG}"
    rc=$?
    if (( rc == 0 )); then
      migrated=1
    fi
    if (( migrated == 0 )); then
      migrate_legacy_creds "${LEGACY_CREDS_DOCKER}" "${LEGACY_CREDS_DOCKER}"
      rc=$?
      (( rc == 0 )) && migrated=1
    fi
    if (( migrated == 0 )); then
      atomic_write "${PROTON_AUTH_FILE}" "# Proton account credentials (do NOT include +pmp)\nPROTON_USER=\nPROTON_PASS=\n"
      warn "Created template ${PROTON_AUTH_FILE}; edit with your Proton credentials"
    fi
  else
    ok "Found ${PROTON_AUTH_FILE}"
  fi
  run chmod 600 "${PROTON_AUTH_FILE}" || run_or_warn sudo chmod 600 "${PROTON_AUTH_FILE}"
}
ensure_proton_auth() {
  step "8/15 Ensuring Proton auth"
  if [[ "${PREFLIGHT_ENSURED_PROTON_AUTH:-0}" = "1" ]]; then
    ok "Proton auth already ensured during preflight"
    return
  fi
  ensure_proton_auth_core
  PREFLIGHT_ENSURED_PROTON_AUTH=1
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
    if run docker run --rm ghcr.io/qdm12/gluetun genkey >/tmp/gl_apikey; then
      GLUETUN_API_KEY="$(cat /tmp/gl_apikey)"
    else
      run openssl rand -base64 48 >/tmp/gl_apikey
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
  local toml='# Gluetun Control-Server RBAC config\n[[roles]]\nname="readonly"\nauth="basic"\nusername="gluetun"\npassword="'"${GLUETUN_API_KEY}"'\nroutes=["GET /v1/openvpn/status","GET /v1/wireguard/status","GET /v1/publicip/ip","GET /v1/openvpn/portforwarded","POST /v1/openvpn/forwardport"]\n'
  atomic_write "${AUTH_DIR}/config.toml" "$toml"
  run chmod 600 "${AUTH_DIR}/config.toml"
}

# ---------------------------[ PORT MONITOR ]-----------------------------------
# ------------------------------[ .ENV FILE ]-----------------------------------
write_env() {
  step "11/15 Writing stack .env"
  local envf="${ARR_ENV_FILE}"
  ensure_dir "${ARR_STACK_DIR}"
  local PU="" PP="" CN="${SERVER_COUNTRIES}"
  if [[ "${UPDATER_PERIOD}" == "0" ]]; then
    warn "UPDATER_PERIOD=0 disables Proton server list updates; adjust in arrconf/userconf.sh if unintended"
  fi
  if [[ -f "${PROTON_AUTH_FILE}" ]]; then
    PU="$(grep -E '^PROTON_USER=' "${PROTON_AUTH_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(grep -E '^PROTON_PASS=' "${PROTON_AUTH_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(printf '%s' "${PP}" | sed 's/\\n$//')"
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
GLUETUN_HEALTH_TARGET=${GLUETUN_HEALTH_TARGET}
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
VPN_TYPE=${VPN_TYPE}
SERVER_COUNTRIES="${CN}"
# Set to 0 to disable periodic Gluetun server updates
UPDATER_PERIOD=${UPDATER_PERIOD}
EOF
  )
  local proton_env="${ARRCONF_DIR}/proton.env"
  if [[ "${VPN_TYPE}" = "openvpn" ]]; then
    [[ -n "${PU}" && -n "${PP}" ]] || die "Missing Proton credentials at ${PROTON_AUTH_FILE}"
    local OUSER
    OUSER="$(ensure_pmp "${PU}")"
    env_content+="
OPENVPN_USER=${OUSER}
OPENVPN_PASSWORD=${PP}"
    atomic_write "${proton_env}" "$(printf 'OPENVPN_USER=%s\nOPENVPN_PASSWORD=%s\n' "${OUSER}" "${PP}")"
  else
    atomic_write "${proton_env}" "# Proton OpenVPN credentials (unused for WireGuard)\n"
    env_content+="
WIREGUARD_MTU=1320"
  fi
  atomic_write "${envf}" "${env_content}\n"
  run chmod 600 "${proton_env}"
  run chmod 600 "${envf}"
  ok "Wrote ${envf}"
}

# Warn if LAN_IP is 0.0.0.0 which exposes services on all interfaces
warn_lan_ip() {
  if [ "${LAN_IP}" = "0.0.0.0" ]; then
    warn "LAN_IP is set to 0.0.0.0 — this would expose the Gluetun API publicly. Set LAN_IP to your LAN interface IP (e.g. 192.168.1.10) for LAN-only access."
  fi
}

# Populate WireGuard variables from a Proton .conf and fail if malformed when VPN_TYPE=wireguard
seed_wireguard_from_conf() {
  local VM CONF K A D
  VM="$(grep -E '^VPN_TYPE=' "${ARR_ENV_FILE}" | cut -d= -f2- \
    || grep -E '^VPN_MODE=' "${ARR_ENV_FILE}" | cut -d= -f2- \
    || echo "${DEFAULT_VPN_TYPE}")"
  if [[ "$VM" = "wireguard" ]]; then
    CONF="$(find_wg_conf "proton.conf" 2>/dev/null)" || die "VPN_TYPE=wireguard but no WireGuard .conf found in ${ARRCONF_DIR}, ${ARR_DOCKER_DIR}/gluetun or ${LEGACY_VPNCONFS_DIR}"
    read -r K A D < <(parse_wg_conf "$CONF" 2>/dev/null) || die "Malformed WireGuard config: $CONF"
    sed -i '/^WIREGUARD_PRIVATE_KEY=/d;/^WIREGUARD_ADDRESSES=/d;/^VPN_DNS_ADDRESS=/d' "${ARR_ENV_FILE}"
    echo "WIREGUARD_PRIVATE_KEY=${K}" >>"${ARR_ENV_FILE}"
    [ -n "$A" ] && echo "WIREGUARD_ADDRESSES=${A}" >>"${ARR_ENV_FILE}"
    [ -n "$D" ] && echo "VPN_DNS_ADDRESS=${D}" >>"${ARR_ENV_FILE}"
    ok "Seeded WG from $(basename "$CONF")"
  fi
}

ensure_qbt_conf_base() {
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

# --- Avoid conflicts: pf-sync sidecar manages the listen port ---
Connection\\UPnP=false
Connection\\UseUPnP=false
Connection\\UseNAT-PMP=false

# --- Paths inside the container ---
Downloads\\SavePath=${QBT_SAVE_PATH}
Downloads\\TempPath=${QBT_TEMP_PATH}
Downloads\\TempPathEnabled=true
CONFEOF
  fi
  chown "${PUID}:${PGID}" "${conf}"
  chmod 0640 "${conf}"
  printf '%s\n' "${conf}"
}

ensure_qbt_conf() {
  ensure_qbt_conf_base >/dev/null
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
  local cfg
  cfg="$(ensure_qbt_conf_base)" || return $?

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
      local host
      host="$(lan_access_host)"
      echo "qBittorrent WebUI → http://${host}:${QBT_HTTP_PORT_HOST}"
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
    profiles: ["bootstrap","prod"]
    cap_add: ["NET_ADMIN"]
    devices:
      - /dev/net/tun:/dev/net/tun
    env_file:
      - ${ARRCONF_DIR}/proton.env
    environment:
      TZ: ${TIMEZONE}
      VPN_SERVICE_PROVIDER: protonvpn
      VPN_TYPE: ${VPN_TYPE}
YAML
    if [ "${VPN_TYPE}" = "wireguard" ]; then
      cat <<'YAML'
      WIREGUARD_PRIVATE_KEY: ${WIREGUARD_PRIVATE_KEY}
      WIREGUARD_ADDRESSES: ${WIREGUARD_ADDRESSES}
      WIREGUARD_MTU: ${WIREGUARD_MTU}
      VPN_DNS_ADDRESS: ${VPN_DNS_ADDRESS}
YAML
    else
      cat <<'YAML'
      VPN_PORT_FORWARDING: "on"
      VPN_PORT_FORWARDING_PROVIDER: protonvpn
      PORT_FORWARD_ONLY: "on"
YAML
    fi
    cat <<'YAML'
      SERVER_COUNTRIES: "${SERVER_COUNTRIES}"
      # FREE_ONLY: "off"
      # DNS & stability
      DOT: "off"
      UPDATER_PERIOD: ${UPDATER_PERIOD}
      HEALTH_TARGET_ADDRESS: ${GLUETUN_HEALTH_TARGET:-1.1.1.1:443}
      HEALTH_VPN_DURATION_INITIAL: 30s
      HEALTH_SUCCESS_WAIT_DURATION: 10s
      # Control server (RBAC)
      HTTP_CONTROL_SERVER_ADDRESS: "${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_LOG: "off"
      HTTP_CONTROL_SERVER_AUTH_FILE: /gluetun/auth/config.toml
      GLUETUN_API_KEY: ${GLUETUN_API_KEY}
      PUID: ${PUID}
      PGID: ${PGID}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
      - ${ARR_DOCKER_DIR}/gluetun/auth:/gluetun/auth
    ports:
      - "${LAN_IP:-0.0.0.0}:${GLUETUN_CONTROL_PORT:-8000}:${GLUETUN_CONTROL_PORT:-8000}"          # Gluetun control API host bind (LAN_IP); clients use lan_access_host()
      - "${LAN_IP:-0.0.0.0}:${QBT_HTTP_PORT_HOST:-8081}:${QBT_WEBUI_PORT:-8080}"   # qB WebUI via gluetun namespace
      - "${LAN_IP:-0.0.0.0}:${SONARR_PORT:-8989}:${SONARR_PORT:-8989}"                    # Sonarr
      - "${LAN_IP:-0.0.0.0}:${RADARR_PORT:-7878}:${RADARR_PORT:-7878}"                    # Radarr
      - "${LAN_IP:-0.0.0.0}:${PROWLARR_PORT:-9696}:${PROWLARR_PORT:-9696}"                    # Prowlarr
      - "${LAN_IP:-0.0.0.0}:${BAZARR_PORT:-6767}:${BAZARR_PORT:-6767}"                    # Bazarr
      - "${LAN_IP:-0.0.0.0}:${FLARESOLVERR_PORT:-8191}:${FLARESOLVERR_PORT:-8191}"                    # FlareSolverr
    healthcheck:
      test: >
        sh -c '
          AUTH="";
          if [ -n "$${GLUETUN_API_KEY}" ]; then
            AUTH="--user gluetun:$${GLUETUN_API_KEY}";
          fi;
          curl -fsS $$AUTH "http://${GLUETUN_CONTROL_HOST:-127.0.0.1}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" >/dev/null &&
YAML
    if [ "${VPN_TYPE}" = "openvpn" ]; then
      cat <<'YAML'
          curl -fsS $$AUTH "http://${GLUETUN_CONTROL_HOST:-127.0.0.1}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status" | grep -qi "running"
YAML
    else
      cat <<'YAML'
          curl -fsS $$AUTH "http://${GLUETUN_CONTROL_HOST:-127.0.0.1}:${GLUETUN_CONTROL_PORT}/v1/wireguard/status" | grep -Eqi "connected|running"
YAML
    fi
    cat <<'YAML'
        '
      interval: 30s
      timeout: 15s
      retries: 10
      start_period: 180s
    restart: unless-stopped

  qbittorrent:
    image: lscr.io/linuxserver/qbittorrent:latest
    container_name: qbittorrent
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      WEBUI_PORT: ${QBT_WEBUI_PORT}
      DOCKER_MODS: ghcr.io/gabe565/linuxserver-mod-vuetorrent
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/qbittorrent:/config
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/version >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 6
      start_period: 90s
    restart: unless-stopped

YAML
    if [ "${VPN_TYPE}" = "openvpn" ]; then
      cat <<'YAML'
  pf-sync:
    image: curlimages/curl:8.8.0
    container_name: pf-sync
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      GLUETUN_CONTROL_HOST: ${GLUETUN_CONTROL_HOST}
      GLUETUN_CONTROL_PORT: ${GLUETUN_CONTROL_PORT}
      GLUETUN_API_KEY: ${GLUETUN_API_KEY}
      QBT_WEBUI_PORT: ${QBT_WEBUI_PORT}
      QBT_USERNAME: ${QBT_USER:-}
      QBT_PASSWORD: ${QBT_PASS:-}
    depends_on:
      gluetun:
        condition: service_healthy
      qbittorrent:
        condition: service_healthy
    command: >
      sh -c '
        echo "[pf-sync] Starting PF-to-qB port synchroniser (adaptive 15-45s backoff)";
        API_ROOT="http://$${GLUETUN_CONTROL_HOST}:$${GLUETUN_CONTROL_PORT}";
        AUTH_HEADER="";
        if [ -n "$${GLUETUN_API_KEY}" ]; then
          AUTH_HEADER="--user gluetun:$${GLUETUN_API_KEY}";
        fi;
        echo "[pf-sync] Waiting for Gluetun health before syncing...";
        until curl -fsS $${AUTH_HEADER} "$${API_ROOT}/v1/openvpn/status" | grep -qi "running"; do
          echo "[pf-sync] Gluetun not ready yet; retrying in 5s";
          sleep 5;
        done;
        echo "[pf-sync] Waiting for qBittorrent API...";
        until curl -fsS "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/app/version" >/dev/null 2>&1; do
          echo "[pf-sync] qBittorrent not ready yet; retrying in 5s";
          sleep 5;
        done;
        CUR="";
        STATE="init";
        LAST_SLEEP="";
        WAIT_DEFAULT=45;
        WAIT_MIN=15;
        WAIT=$$WAIT_DEFAULT;
        LAST_BAD="";
        while :; do
          RAW=$$(curl -fsS $${AUTH_HEADER} "$${API_ROOT}/v1/openvpn/portforwarded" || true)
          RAW=$$(printf '%s' "$$RAW" | tr -d '\r\n')
          case "$$RAW" in
            *:*) P=$${RAW##*:} ;;
            *)   P="$$RAW" ;;
          esac
          if printf '%s' "$$P" | grep -Eq "^[1-9][0-9]{3,4}$"; then
            if [ "$$P" != "$$CUR" ]; then
              echo "[pf-sync] Applying Proton PF port $$P to qBittorrent";
              if [ -n "$${QBT_USERNAME}" ] && [ -n "$${QBT_PASSWORD}" ]; then
                curl -fsS -c /tmp/qbt.cookie "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/auth/login" \
                  --data "username=$${QBT_USERNAME}&password=$${QBT_PASSWORD}" >/dev/null 2>&1 && \
                curl -fsS -b /tmp/qbt.cookie \
                  "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/app/setPreferences" \
                  --data "json={\\"listen_port\\":$${P},\\"upnp\\":false}" >/dev/null 2>&1;
              else
                curl -fsS -X POST \
                  "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/app/setPreferences" \
                  --data "json={\\"listen_port\\":$${P},\\"upnp\\":false}" >/dev/null 2>&1;
              fi;
              CUR="$$P";
            fi;
            curl -fsS $${AUTH_HEADER} -X POST "$${API_ROOT}/v1/openvpn/forwardport" >/dev/null 2>&1 || true;
            if [ "$$STATE" != "ready" ]; then
              echo "[pf-sync] PF port confirmed at $$P";
            fi;
            STATE="ready";
            LAST_BAD="";
            WAIT=$$WAIT_DEFAULT;
          else
            if [ "$$STATE" != "waiting" ] || [ "$$LAST_BAD" != "$$RAW" ]; then
              echo "[pf-sync] PF port not available yet (value='$$RAW')";
            fi;
            PREV_STATE=$$STATE;
            STATE="waiting";
            LAST_BAD="$$RAW";
            if [ "$$PREV_STATE" != "waiting" ]; then
              WAIT=$$WAIT_MIN;
            elif [ "$$WAIT" -lt "$$WAIT_DEFAULT" ]; then
              WAIT=$$((WAIT * 2));
              if [ "$$WAIT" -gt "$$WAIT_DEFAULT" ]; then
                WAIT=$$WAIT_DEFAULT;
              fi;
            fi;
          fi;
          if [ "$$LAST_SLEEP" != "$${WAIT}:$${STATE}" ]; then
            echo "[pf-sync] Sleeping $${WAIT}s before next check";
            LAST_SLEEP="$${WAIT}:$${STATE}";
          fi;
          sleep "$$WAIT";
        done'
    healthcheck:
      test: >
        sh -c '
          AUTH="";
          if [ -n "$${GLUETUN_API_KEY}" ]; then
            AUTH="--user gluetun:$${GLUETUN_API_KEY}";
          fi;
          curl -fsS $$AUTH "http://$${GLUETUN_CONTROL_HOST}:$${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded" | grep -Eq "(^|:)[1-9][0-9]{3,4}$"
        '
      interval: 45s
      timeout: 10s
      retries: 5
      start_period: 90s
    restart: unless-stopped
YAML
    fi
    cat <<'YAML'

  sonarr:
    image: lscr.io/linuxserver/sonarr:latest
    container_name: sonarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${TV_DIR}:/tv
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:${SONARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  radarr:
    image: lscr.io/linuxserver/radarr:latest
    container_name: radarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${MOVIES_DIR}:/movies
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:${RADARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  prowlarr:
    image: lscr.io/linuxserver/prowlarr:latest
    container_name: prowlarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on:
      gluetun:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:${PROWLARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  bazarr:
    image: lscr.io/linuxserver/bazarr:latest
    container_name: bazarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
      - ${SUBS_DIR}:/subs
    depends_on:
      gluetun:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:${BAZARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  flaresolverr:
    image: ghcr.io/flaresolverr/flaresolverr:latest
    container_name: flaresolverr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: info
    depends_on:
      gluetun:
        condition: service_started
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:${FLARESOLVERR_PORT} >/dev/null"]
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
  VM="$(grep -E '^VPN_TYPE=' "$ENVF" | cut -d= -f2- \
    || grep -E '^VPN_MODE=' "$ENVF" | cut -d= -f2- \
    || echo "${DEFAULT_VPN_TYPE}")"
  if [[ "$VM" = openvpn ]]; then
    local OU OP
    OU="$(grep -E '^OPENVPN_USER=' "$ENVF" | cut -d= -f2- || true)"
    OP="$(grep -E '^OPENVPN_PASSWORD=' "$ENVF" | cut -d= -f2- || true)"
    if [[ -z "${OU}" || -z "${OP}" ]]; then
      die "Proton credentials missing. Edit ${PROTON_AUTH_FILE} then re-run."
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
  note "Image downloads can be time-consuming; please wait"
  if ! compose_cmd pull; then
    warn "Pull failed; will rely on up"
  fi
}
start_with_checks() {
  step "14/15 Starting the stack with enhanced health monitoring"
  validate_creds_or_die
  local MAX_RETRIES=5 RETRY=0 requires_pf
  requires_pf="$([ "${VPN_TYPE}" = "openvpn" ] && echo 1 || echo 0)"
  while [[ $RETRY -lt $MAX_RETRIES ]]; do
    note "→ Attempt $((RETRY + 1))/${MAX_RETRIES}"
    run_or_warn compose_cmd --profile bootstrap config --services
    run_or_warn compose_cmd --profile bootstrap config
    run_or_warn compose_cmd --profile bootstrap up -d
    run_or_warn compose_cmd ps
    run_or_warn docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    if ! is_dry && ! docker ps --format '{{.Names}}' | grep -q 'gluetun'; then
      die "Gluetun container failed to start"
    fi
    local health_window=$((180 + 10 * 30))
    local max_wait=$((health_window + 120))
    if ! docker image inspect qmcgaw/gluetun:v3.38.0 >/dev/null 2>&1; then
      max_wait=$((max_wait + 60))
    fi
    note "Waiting for gluetun to report healthy (up to ${max_wait}s)..."
    local waited=0 HEALTH="unknown" IP="" PF="" pf_raw=""
    local ctrl_host="${GLUETUN_CONTROL_HOST:-127.0.0.1}"
    local ctrl_port="${GLUETUN_CONTROL_PORT:-8000}"
    local -a curl_cmd=(curl -fsS)
    if [ -n "${GLUETUN_API_KEY:-}" ]; then
      curl_cmd+=(--user "gluetun:${GLUETUN_API_KEY}")
    fi
    while [[ $waited -lt ${max_wait} ]]; do
      HEALTH="$(docker inspect gluetun --format='{{.State.Health.Status}}' 2>/dev/null || echo unknown)"
      IP="$("${curl_cmd[@]}" "http://${ctrl_host}:${ctrl_port}/v1/publicip/ip" 2>/dev/null || true)"
      if (( requires_pf )); then
        pf_raw="$("${curl_cmd[@]}" "http://${ctrl_host}:${ctrl_port}/v1/openvpn/portforwarded" 2>/dev/null || true)"
        pf_raw="$(printf '%s' "$pf_raw" | tr -d '\r\n')"
        PF=""
        case "$pf_raw" in
          *:*) PF="${pf_raw##*:}" ;;
          *)   PF="$pf_raw" ;;
        esac
        if ! printf '%s' "$PF" | grep -Eq '^[1-9][0-9]{3,4}$'; then
          PF=""
        fi
      fi
      if [[ "$HEALTH" = healthy && -n "$IP" ]]; then
        break
      fi
      sleep 5
      waited=$((waited + 5))
    done
    if [[ "$HEALTH" = healthy && -n "$IP" ]]; then
      ok "Gluetun healthy; IP: ${IP}${PF:+, PF: ${PF}}"
      break
    fi
    warn "Gluetun not healthy yet; down & retry"
    run_or_warn compose_cmd down >/dev/null 2>&1
    clear_port_conflicts
    RETRY=$((RETRY + 1))
  done
  if [[ "$HEALTH" != healthy ]]; then
    if (( requires_pf )); then
      warn "Troubleshooting hint: docker exec gluetun curl -fsS http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status"
      warn "Troubleshooting hint: docker exec gluetun curl -fsS http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded"
    else
      warn "Troubleshooting hint: docker exec gluetun curl -fsS http://${GLUETUN_CONTROL_HOST}:${GLUETUN_CONTROL_PORT}/v1/wireguard/status"
    fi
    die "Gluetun did not achieve connectivity; check: docker logs gluetun"
  fi
  compose_cmd --profile prod up -d || die "Failed to start stack"
  note "Remaining services (prod profile) launched; health checks may take up to 90s"
  print_qbt_temp_password_if_any
  if [ -n "${QBT_USER:-}" ] && [ -n "${QBT_PASS:-}" ]; then
    ok "qBittorrent credentials preseeded"
  fi
  run_or_warn compose_cmd ps
  local ip pf_port="" client_host
  client_host="$(lan_access_host)"
  local -a post_curl=(curl -fsS)
  if [ -n "${GLUETUN_API_KEY:-}" ]; then
    post_curl+=(--user "gluetun:${GLUETUN_API_KEY}")
  fi
  ip="$("${post_curl[@]}" "http://${client_host}:${GLUETUN_CONTROL_PORT:-8000}/v1/publicip/ip" 2>/dev/null || true)"
  note "Public IP: ${ip}"
  if (( requires_pf )); then
    pf_raw="$("${post_curl[@]}" "http://${client_host}:${GLUETUN_CONTROL_PORT:-8000}/v1/openvpn/portforwarded" 2>/dev/null || true)"
    pf_raw="$(printf '%s' "$pf_raw" | tr -d '\r\n')"
    case "$pf_raw" in
      *:*) pf_port="${pf_raw##*:}" ;;
      *)   pf_port="$pf_raw" ;;
    esac
    if printf '%s' "$pf_port" | grep -Eq '^[1-9][0-9]{3,4}$'; then
      if [[ "$pf_raw" != "$pf_port" && -n "$pf_raw" ]]; then
        note "Forwarded port: ${pf_port} (${pf_raw})"
      else
        note "Forwarded port: ${pf_port}"
      fi
    else
      note "Forwarded port response: ${pf_raw}"
    fi
  else
    note "WireGuard mode detected; Proton port forwarding not applicable."
  fi
}

install_aliases() {
  step "15/15 Installing ARR helper aliases"
  local src
  src="$(dirname "${BASH_SOURCE[0]}")/.aliasarr"
  local dst="${ARR_STACK_DIR}/.aliasarr"
  run cp "$src" "$dst" || warn "Failed to copy alias file"
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
  preflight
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
  note "  • qB Web UI: http://${LOCALHOST_NAME}:${QBT_HTTP_PORT_HOST} (use printed admin password or preset QBT_USER/QBT_PASS)."
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
