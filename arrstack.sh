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

umask 077
export HISTFILE=/dev/null
set +o history 2>/dev/null || true

: "${DEBUG:=0}"
: "${KEEP_LOG:=0}"

export DEBUG KEEP_LOG

USER_LOG_FILE_ENV="${LOG_FILE:-}"
LOG_FILE=/dev/null
TMP_LOG=""
DEST_LOG=""

if [[ "${DEBUG}" == "1" ]]; then
  KEEP_LOG=1
  export KEEP_LOG
fi
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

redact_secrets() {
  sed -E 's/(GLUETUN_API_KEY|OPENVPN_PASSWORD|OPENVPN_USER|QBT_PASS|PROTON_PASS|PROTON_USER)=[^[:space:]]+/\1=<REDACTED>/g'
}

_log_cmd() {
  local -a argv=("$@")
  printf '+ %s\n' "$(_stringify_cmd "${argv[@]}")" | redact_secrets >>"$LOG_FILE" 2>/dev/null || true
}

_exec_simple() {
  local -a argv=("$@")
  _log_cmd "${argv[@]}"
  if is_dry; then
    return 0
  fi
  "${argv[@]}"
}

run() {
  _exec_simple "$@"
}

run_or_warn() {
  if ! _exec_simple "$@"; then
    local rc=$?
    local cmd_str
    cmd_str="$(_stringify_cmd "$@")"
    cmd_str="$(printf '%s\n' "$cmd_str" | redact_secrets)"
    warn "Command failed (${rc}): ${cmd_str}"
    return "$rc"
  fi
}

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
export QBT_WEBUI_PORT QBT_HTTP_PORT_HOST QBT_USER QBT_PASS QBT_SAVE_PATH QBT_TEMP_PATH LAN_IP ARR_BIND_ADDRESS SONARR_BIND_ADDRESS RADARR_BIND_ADDRESS PROWLARR_BIND_ADDRESS BAZARR_BIND_ADDRESS LOCALHOST_ADDR LOCALHOST_NAME GLUETUN_CONTROL_PORT GLUETUN_CONTROL_BIND_HOST GLUETUN_CONTROL_LISTEN_ADDR GLUETUN_CONTROL_HOST GLUETUN_HEALTH_TARGET GLUETUN_FIREWALL_OUTBOUND_SUBNETS GLUETUN_FIREWALL_INPUT_PORTS GLUETUN_HTTPPROXY GLUETUN_SHADOWSOCKS PUID PGID TIMEZONE UPDATER_PERIOD
export SONARR_PORT RADARR_PORT PROWLARR_PORT BAZARR_PORT FLARESOLVERR_PORT
export DEFAULT_VPN_TYPE SERVER_COUNTRIES SERVER_HOSTNAMES DEFAULT_COUNTRY GLUETUN_API_KEY

: "${GLUETUN_IMAGE:=qmcgaw/gluetun:v3.38.0}"
: "${QBITTORRENT_IMAGE:=lscr.io/linuxserver/qbittorrent:latest}"
: "${QBT_DOCKER_MODS:=ghcr.io/gabe565/linuxserver-mod-vuetorrent}"
: "${PF_SYNC_IMAGE:=curlimages/curl:8.8.0}"
: "${SONARR_IMAGE:=lscr.io/linuxserver/sonarr:latest}"
: "${RADARR_IMAGE:=lscr.io/linuxserver/radarr:latest}"
: "${PROWLARR_IMAGE:=lscr.io/linuxserver/prowlarr:latest}"
: "${BAZARR_IMAGE:=lscr.io/linuxserver/bazarr:latest}"
: "${FLARESOLVERR_IMAGE:=ghcr.io/flaresolverr/flaresolverr:latest}"
export GLUETUN_IMAGE QBITTORRENT_IMAGE QBT_DOCKER_MODS PF_SYNC_IMAGE SONARR_IMAGE RADARR_IMAGE PROWLARR_IMAGE BAZARR_IMAGE FLARESOLVERR_IMAGE

# non-interactive mode & key-rotation control
: "${ARR_NONINTERACTIVE:=0}"
: "${FORCE_ROTATE_API_KEY:=0}"
LAN_IP_ALL_INTERFACES=0

# ----------------------------[ LOGGING ]---------------------------------------
log_dest_is_allowed() {
  local candidate="$1"
  local arr_dir="${ARR_STACK_DIR%/}"
  if [[ -z "$arr_dir" ]]; then
    arr_dir="${ARR_STACK_DIR}"
  fi
  [[ -n "$candidate" ]] || return 1
  [[ "$candidate" == /* ]] || return 1
  [[ -n "$arr_dir" ]] || return 1
  [[ "$arr_dir" == /* ]] || return 1
  case "$candidate" in
    "$arr_dir"/*) return 0 ;;
  esac
  return 1
}

setup_logging() {
  if [[ "${DEBUG}" != "1" ]]; then
    LOG_FILE=/dev/null
    TMP_LOG=""
    DEST_LOG=""
    export LOG_FILE
    return
  fi

  local tmp=""
  if tmp=$(mktemp -p /dev/shm arrstack.XXXXXX.log 2>/dev/null); then
    :
  elif tmp=$(mktemp /tmp/arrstack.XXXXXX.log 2>/dev/null); then
    :
  else
    die "Unable to create temporary log file"
  fi

  chmod 600 "$tmp" || die "Unable to secure temporary log file"
  TMP_LOG="$tmp"
  LOG_FILE="$TMP_LOG"

  local dest="" arr_dir="${ARR_STACK_DIR%/}"
  if [[ -z "$arr_dir" ]]; then
    arr_dir="${ARR_STACK_DIR}"
  fi
  if [[ -n "${LOG_FILE_DEST:-}" ]] && log_dest_is_allowed "$LOG_FILE_DEST"; then
    dest="$LOG_FILE_DEST"
  elif [[ -n "$USER_LOG_FILE_ENV" ]] && log_dest_is_allowed "$USER_LOG_FILE_ENV"; then
    dest="$USER_LOG_FILE_ENV"
  else
    [[ -n "$arr_dir" ]] || die "ARR_STACK_DIR is not set"
    [[ "$arr_dir" == /* ]] || die "ARR_STACK_DIR must be an absolute path"
    dest="${arr_dir}/arrstack-$(date -u +%Y%m%d-%H%M%S).log"
  fi

  DEST_LOG="$dest"
  mkdir -p "$(dirname "$DEST_LOG")"
  export LOG_FILE
}

ts() {
  local now diff
  now=$(date +%s)
  diff=$((now - SCRIPT_START))
  printf '%02d:%02d' $((diff / 60)) $((diff % 60))
}

out() {
  printf "%b\n" "$1" | redact_secrets >>"${LOG_FILE}" 2>/dev/null || true
  printf "%b\n" "$1"
}

step() { out "$(ts) ${C_BLUE}${C_BOLD}✴️ $1${C_RESET}"; }
note() { out "$(ts) ${C_BLUE}➤ $1${C_RESET}"; }
ok() { out "$(ts) ${C_GREEN}✔ $1${C_RESET}"; }

# shellcheck disable=SC2015
trace() { [ "$DEBUG" = "1" ] && printf "[trace] %s\n" "$1" >>"${LOG_FILE}" || true; }

print_help() {
  cat <<'EOF'
Usage: ./arrstack.sh [options] [subcommand]

Options:
  --openvpn                           Pin VPN_TYPE=openvpn for this run.
  --wireguard                         Pin VPN_TYPE=wireguard for this run.
  --debug                             Enable verbose logging and keep the installer log.
  -y, --yes                           Auto-confirm prompts and run non-interactively (sets
                                      ASSUME_YES=1 and ARR_NONINTERACTIVE=1).
  --no-prompt, --non-interactive      Skip interactive questions; still reuses any existing
                                      Gluetun API key unless you also rotate it.
  --rotate-apikey, --rotate-api-key,
  --rotate-key                        Force regeneration of the Gluetun API key on this run.
  -h, --help                          Show this message and exit.

Subcommands:
  conf-diff                           Compare userconf.sh to the latest defaults and exit.

Examples:
  ./arrstack.sh --openvpn
  ASSUME_YES=1 ./arrstack.sh --no-prompt
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --openvpn)
        VPN_TYPE="openvpn"
        ;;
      --wireguard)
        VPN_TYPE="wireguard"
        ;;
      --debug)
        DEBUG=1
        KEEP_LOG=1
        export DEBUG KEEP_LOG
        ;;
      -y|--yes)
        ASSUME_YES=1
        ARR_NONINTERACTIVE=1
        export ASSUME_YES
        ;;
      --no-prompt|--non-interactive)
        ARR_NONINTERACTIVE=1
        ASSUME_YES=1
        export ASSUME_YES
        ;;
      --rotate-apikey|--rotate-api-key|--rotate-key)
        FORCE_ROTATE_API_KEY=1
        ;;
      -h|--help)
        print_help
        exit 0
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

# ----------[ API KEY PREFLIGHT ]----------
mask_key() {
  local k="${1:-}" n
  n=${#k}
  if (( n <= 8 )); then
    printf '%s' '********'
  else
    printf '%s…%s' "${k:0:4}" "${k: -4}"
  fi
}

is_valid_gluetun_key() {
  local key="${1:-}"
  [[ -n "$key" ]] || return 1
  [[ ${#key} -ge 32 ]] || return 1
  [[ "$key" =~ ^[A-Za-z0-9+/=]+$ ]] || return 1
  return 0
}

generate_local_gluetun_key() {
  local key="" rc=0
  local -a cmd=(openssl rand -base64 48)
  _log_cmd "${cmd[@]}"
  key="$("${cmd[@]}" | tr -d '\r\n')" || rc=$?
  if (( rc != 0 )) || ! is_valid_gluetun_key "$key"; then
    return 1
  fi
  printf '%s' "$key"
}

read_tty() {
  local prompt="$1" var="$2" ans=""
  if [ -t 0 ] && [ -r /dev/tty ]; then
    printf "%s" "$prompt" >/dev/tty
    if ! IFS= read -r ans </dev/tty; then
      ans=""
    fi
  else
    printf "%s" "$prompt" >&2
    if ! IFS= read -r ans; then
      ans=""
    fi
  fi
  printf -v "$var" '%s' "$ans"
}

preflight_gluetun_apikey() {
  local toml="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"
  local key_env="" key_toml="" chosen="" ans=""
  if [ -f "${ARR_ENV_FILE}" ]; then
    key_env="$(grep -E '^GLUETUN_API_KEY=' "${ARR_ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"\r' || true)"
  fi
  if [ -f "${toml}" ]; then
    key_toml="$(sed -nE 's/^[[:space:]]*password="([^"]+)".*/\1/p' "${toml}" | tail -n1 || true)"
  fi
  if [ -n "${key_toml}" ] && [ -n "${key_env}" ] && [ "${key_toml}" != "${key_env}" ]; then
    warn "GLUETUN_API_KEY mismatch between .env and auth/config.toml; will prefer the TOML value."
  fi
  chosen="${key_toml:-$key_env}"

  if [ "${FORCE_ROTATE_API_KEY}" = "1" ]; then
    GLUETUN_API_KEY=""
    return
  fi
  if [ -z "${chosen}" ]; then
    note "No existing GLUETUN_API_KEY found; will generate a new one."
    return
  fi
  if [ "${ARR_NONINTERACTIVE}" = "1" ]; then
    GLUETUN_API_KEY="${chosen}"
    return
  fi
  read_tty "Reuse existing GLUETUN_API_KEY ($(mask_key "${chosen}"))? [Y/n] " ans
  if [[ "${ans}" =~ ^[Nn]$ ]]; then
    note "Will generate a new GLUETUN_API_KEY for Gluetun control."
    GLUETUN_API_KEY=""
    FORCE_ROTATE_API_KEY=1
  else
    GLUETUN_API_KEY="${chosen}"
  fi
}

have_ip() {
  local needle="$1"
  [[ -n "${needle}" ]] || return 1
  ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$needle"
}

is_private_ipv4() {
  local ip="$1"
  case "$ip" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*)
      return 0 ;;
    *)
      return 1 ;;
  esac
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

control_access_host() {
  local host="${GLUETUN_CONTROL_BIND_HOST:-}"
  if [[ -z "$host" || "$host" = "0.0.0.0" ]]; then
    host="${LAN_IP:-}"
  fi
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
  printf 'Proceed with installation? [y/N]: '
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

  local ctrl_port ctrl_host_bind ctrl_client_host ctrl_container_bind
  local lan_host_bind lan_access_host_resolved
  ctrl_port="${GLUETUN_CONTROL_PORT:-8000}"
  ctrl_host_bind="${GLUETUN_CONTROL_BIND_HOST:-${LAN_IP:-0.0.0.0}}"
  ctrl_client_host="$(control_access_host)"
  ctrl_container_bind="${GLUETUN_CONTROL_LISTEN_ADDR:-127.0.0.1}"
  lan_host_bind="${LAN_IP:-0.0.0.0}"
  lan_access_host_resolved="$(lan_access_host)"

  note "Summary:"
  note "  • VPN_TYPE=${VPN_TYPE}"
  note "  • LAN_IP binding for service UIs: ${lan_host_bind}"
  note "  • Control API: container bind ${ctrl_container_bind}:${ctrl_port}; host ${ctrl_host_bind}:${ctrl_port}; client URL http://${ctrl_client_host}:${ctrl_port}"
  note "  • qB Web UI: host ${lan_host_bind}:${QBT_HTTP_PORT_HOST}; container ${QBT_WEBUI_PORT}; access URL http://${lan_access_host_resolved}:${QBT_HTTP_PORT_HOST}"
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
      atomic_write "${PROTON_AUTH_FILE}" "$(cat <<'EOF'
# Proton account credentials (do NOT include +pmp)
PROTON_USER=
PROTON_PASS=
EOF
)"
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
  local previous="${GLUETUN_API_KEY:-}"
  local need_new=0

  if [[ -z "${previous}" ]] && [[ -f "${ARR_ENV_FILE}" ]]; then
    previous="$(grep -E '^GLUETUN_API_KEY=' "${ARR_ENV_FILE}" | tail -n1 | cut -d= -f2- | tr -d '"\r\n' || true)"
  fi

  if [[ -n "${previous}" ]] && ! is_valid_gluetun_key "${previous}"; then
    warn "Existing GLUETUN_API_KEY is malformed; generating a fresh key."
    previous=""
    need_new=1
  fi

  if [[ "${FORCE_ROTATE_API_KEY:-0}" = "1" ]]; then
    need_new=1
  elif [[ -z "${previous}" ]]; then
    need_new=1
  fi

  if (( need_new )); then
    if is_dry; then
      GLUETUN_API_KEY="${previous:-BASE64PLACEHOLDERAAAAAAAAAAAAAAAAAAAAAA==}"
      export GLUETUN_API_KEY
      ok "[DRY] Using placeholder API key (length ${#GLUETUN_API_KEY})"
      return
    fi

    local generated="" rc=0
    local -r gluetun_image="${GLUETUN_IMAGE}"
    if command -v docker >/dev/null 2>&1; then
      if ! docker image inspect "${gluetun_image}" >/dev/null 2>&1; then
        _log_cmd docker pull "${gluetun_image}"
        docker pull "${gluetun_image}" >/dev/null 2>&1 || true
      fi
      local -a genkey_cmd=(docker run --rm "${gluetun_image}" genkey)
      _log_cmd "${genkey_cmd[@]}"
      generated="$("${genkey_cmd[@]}" 2>/dev/null | tail -n1 | tr -d '\r\n')" || rc=$?
      if (( rc != 0 )) || ! is_valid_gluetun_key "${generated}"; then
        generated=""
      fi
    fi

    if [[ -z "${generated}" ]]; then
      warn "docker-based API key generation failed or is unavailable; falling back to openssl."
      generated="$(generate_local_gluetun_key)" || die "Failed to generate Gluetun API key with openssl."
    fi

    if [[ -n "${previous}" && "${generated}" = "${previous}" ]]; then
      warn "Generated API key matched existing value; regenerating locally."
      generated="$(generate_local_gluetun_key)" || die "Failed to regenerate Gluetun API key with openssl."
    fi

    GLUETUN_API_KEY="${generated}"
    export GLUETUN_API_KEY
    ok "Generated new API key (length ${#GLUETUN_API_KEY})"
  else
    GLUETUN_API_KEY="$(printf '%s' "${previous}" | tr -d '\r\n')"
    export GLUETUN_API_KEY
    ok "Reusing existing API key (length ${#GLUETUN_API_KEY})"
  fi
}
write_gluetun_auth() {
  step "10/15 Writing Gluetun RBAC config"
  local AUTH_DIR="${ARR_DOCKER_DIR}/gluetun/auth"
  ensure_dir "$AUTH_DIR"
  local toml
  toml=$(cat <<EOF
# Gluetun Control-Server RBAC config
[[roles]]
name="readonly"
auth="basic"
username="gluetun"
password="${GLUETUN_API_KEY}"
routes=[
  "GET /v1/openvpn/status",
  "GET /v1/wireguard/status",
  "GET /v1/publicip/ip",
  "GET /v1/openvpn/portforwarded",
  "POST /v1/openvpn/forwardport"
]
EOF
)
  atomic_write "${AUTH_DIR}/config.toml" "$toml"
  run chmod 600 "${AUTH_DIR}/config.toml"
}

# ---------------------------[ PORT MONITOR ]-----------------------------------
# ------------------------------[ .ENV FILE ]-----------------------------------
write_env() {
  step "11/15 Writing stack .env"
  local envf="${ARR_ENV_FILE}"
  ensure_dir "${ARR_STACK_DIR}"
  local PU="" PP="" CN="${SERVER_COUNTRIES}" SHN="${SERVER_HOSTNAMES:-}"
  CN="${CN%\"}"
  CN="${CN#\"}"
  CN="$(printf '%s' "${CN}" | sed -E 's/, +/,/g')"
  SHN="${SHN%\"}"
  SHN="${SHN#\"}"
  SHN="$(printf '%s' "${SHN}" | sed -E 's/, +/,/g')"
  if [[ "${UPDATER_PERIOD}" == "0" ]]; then
    warn "UPDATER_PERIOD=0 disables Proton server list updates; adjust in arrconf/userconf.sh if unintended"
  fi
  if [[ -f "${PROTON_AUTH_FILE}" ]]; then
    PU="$(grep -E '^PROTON_USER=' "${PROTON_AUTH_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(grep -E '^PROTON_PASS=' "${PROTON_AUTH_FILE}" | cut -d= -f2- | tr -d '"' || true)"
    PP="$(printf '%s' "${PP}" | sed 's/\\n$//')"
  fi
  local env_extra="" OUSER=""
  local proton_env="${ARRCONF_DIR}/proton.env"
  if [[ "${VPN_TYPE}" = "openvpn" ]]; then
    [[ -n "${PU}" && -n "${PP}" ]] || die "Missing Proton credentials at ${PROTON_AUTH_FILE}"
    OUSER="$(ensure_pmp "${PU}")"
    env_extra="$(cat <<EOF

OPENVPN_USER=${OUSER}
OPENVPN_PASSWORD=${PP}
EOF
)"
    atomic_write "${proton_env}" "$(cat <<EOF
OPENVPN_USER=${OUSER}
OPENVPN_PASSWORD=${PP}
EOF
)"
  else
    env_extra="$(cat <<'EOF'

WIREGUARD_MTU=1320
EOF
)"
    atomic_write "${proton_env}" "$(cat <<'EOF'
# Proton OpenVPN credentials (unused for WireGuard)
EOF
)"
  fi
  local env_body
  env_body="$({
    cat <<EOF
# IDs & timezone
PUID=${PUID}
PGID=${PGID}
TIMEZONE=${TIMEZONE}

# Gluetun Control-Server API key
GLUETUN_API_KEY=${GLUETUN_API_KEY}

# Container images
GLUETUN_IMAGE=${GLUETUN_IMAGE}
QBITTORRENT_IMAGE=${QBITTORRENT_IMAGE}
QBT_DOCKER_MODS=${QBT_DOCKER_MODS}
PF_SYNC_IMAGE=${PF_SYNC_IMAGE}
SONARR_IMAGE=${SONARR_IMAGE}
RADARR_IMAGE=${RADARR_IMAGE}
PROWLARR_IMAGE=${PROWLARR_IMAGE}
BAZARR_IMAGE=${BAZARR_IMAGE}
FLARESOLVERR_IMAGE=${FLARESOLVERR_IMAGE}

# Network and qBittorrent
GLUETUN_CONTROL_PORT=${GLUETUN_CONTROL_PORT}
GLUETUN_CONTROL_BIND_HOST=${GLUETUN_CONTROL_BIND_HOST}
GLUETUN_CONTROL_LISTEN_ADDR=${GLUETUN_CONTROL_LISTEN_ADDR}
QBT_HTTP_PORT_HOST=${QBT_HTTP_PORT_HOST}
QBT_WEBUI_PORT=${QBT_WEBUI_PORT}
GLUETUN_CONTROL_HOST=${GLUETUN_CONTROL_HOST}
GLUETUN_HEALTH_TARGET=${GLUETUN_HEALTH_TARGET}
GLUETUN_FIREWALL_OUTBOUND_SUBNETS=${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}
GLUETUN_FIREWALL_INPUT_PORTS=${GLUETUN_FIREWALL_INPUT_PORTS}
GLUETUN_HTTPPROXY=${GLUETUN_HTTPPROXY}
GLUETUN_SHADOWSOCKS=${GLUETUN_SHADOWSOCKS}
QBT_USER=${QBT_USER}
QBT_PASS=${QBT_PASS}
LAN_IP=${LAN_IP}
ARR_BIND_ADDRESS=${ARR_BIND_ADDRESS}
SONARR_BIND_ADDRESS=${SONARR_BIND_ADDRESS}
RADARR_BIND_ADDRESS=${RADARR_BIND_ADDRESS}
PROWLARR_BIND_ADDRESS=${PROWLARR_BIND_ADDRESS}
BAZARR_BIND_ADDRESS=${BAZARR_BIND_ADDRESS}
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
SERVER_COUNTRIES=${CN}
SERVER_HOSTNAMES=${SHN}
# Set to 0 to disable periodic Gluetun server updates
UPDATER_PERIOD=${UPDATER_PERIOD}
EOF
    printf '%s' "${env_extra}"
  })"
  atomic_write "${envf}" "${env_body}"
  run chmod 600 "${proton_env}"
  run chmod 600 "${envf}"
  ok "Wrote ${envf}"
}

# Warn if LAN_IP is 0.0.0.0 which exposes services on all interfaces
warn_lan_ip() {
  if [ "${LAN_IP}" = "0.0.0.0" ]; then
    warn "LAN_IP is set to 0.0.0.0 — this exposes every published service port. Set LAN_IP to your LAN adapter (e.g. 192.168.1.10) unless you intend to listen on all interfaces."
    LAN_IP_ALL_INTERFACES=1
  elif [[ -n "${LAN_IP}" ]] && ! is_private_ipv4 "${LAN_IP}"; then
    warn "LAN_IP=${LAN_IP} is not an RFC1918 address; ensure you intend to expose the stack beyond your LAN."
  fi
}

verify_gluetun_control_security() {
  local ctrl_port host_bind access_host auth_file scope="LAN-only" container_bind
  ctrl_port="${GLUETUN_CONTROL_PORT:-8000}"
  host_bind="${GLUETUN_CONTROL_BIND_HOST:-${LAN_IP:-0.0.0.0}}"
  access_host="$(control_access_host)"
  container_bind="${GLUETUN_CONTROL_LISTEN_ADDR:-127.0.0.1}"
  auth_file="${ARR_DOCKER_DIR}/gluetun/auth/config.toml"

  if [[ -z "${GLUETUN_API_KEY:-}" ]]; then
    die "GLUETUN_API_KEY is empty; refusing to start Gluetun control API without RBAC."
  fi

  if ! is_dry; then
    if [ ! -s "${auth_file}" ]; then
      die "Gluetun RBAC config missing at ${auth_file}; remove ${ARR_DOCKER_DIR}/gluetun/auth and re-run the installer."
    fi
  else
    note "[DRY] Skipping RBAC config presence check (dry run)."
  fi

  if [[ "${host_bind}" = "0.0.0.0" ]]; then
    scope="all host interfaces"
  elif [[ "${host_bind}" = "${LOCALHOST_ADDR:-127.0.0.1}" ]] || [[ "${host_bind}" = 127.* ]] || [[ "${host_bind}" = localhost ]]; then
    scope="loopback-only"
  elif ! is_private_ipv4 "${host_bind}"; then
    scope="non-RFC1918 (public)"
  fi

  note "Control API mapping: container ${container_bind}:${ctrl_port} → host ${host_bind}:${ctrl_port} (${scope})."
  if [[ "${host_bind}" = "0.0.0.0" && "${LAN_IP_ALL_INTERFACES:-0}" != "1" ]]; then
    warn "Control API host bind resolved to 0.0.0.0 — set GLUETUN_CONTROL_BIND_HOST (or LAN_IP) to a LAN or loopback address for tighter exposure."
  elif [[ "${scope}" = "non-RFC1918 (public)" ]]; then
    warn "Control API host bind ${host_bind} is public — restrict GLUETUN_CONTROL_BIND_HOST or add firewall rules."
  fi

  if [[ "${container_bind}" = "0.0.0.0" ]]; then
    warn "Control server is listening on all container interfaces; set GLUETUN_CONTROL_LISTEN_ADDR=127.0.0.1 to keep it private."
  elif [[ "${container_bind}" != "127.0.0.1" && "${container_bind}" != "localhost" ]]; then
    warn "Control server listens on ${container_bind}; ensure this is an intentional override."
  fi

  local key_len=${#GLUETUN_API_KEY}
  if (( key_len < 24 )); then
    warn "GLUETUN_API_KEY length (${key_len}) is shorter than recommended (>=24). Run ./arrstack.sh --rotate-apikey to regenerate."
  fi
  note "RBAC: enabled via ${auth_file} (API key length ${key_len})."
  note "Access from host: http://${access_host}:${ctrl_port}/v1/publicip/ip"
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
WebUI\\AlternativeUIEnabled=false
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

verify_qbt_credentials_for_pf_sync() {
  local cfg stored_user hash_line payload salt_b64 dk_b64 salt_hex derived

  cfg="$(ensure_qbt_conf_base)" || return

  if [ -z "${QBT_USER:-}" ] && [ -z "${QBT_PASS:-}" ]; then
    note "QBT_USER/QBT_PASS not set; pf-sync will rely on qBittorrent's local-auth bypass."
    return
  fi

  if [ -z "${QBT_USER:-}" ] || [ -z "${QBT_PASS:-}" ]; then
    warn "Both QBT_USER and QBT_PASS must be populated for pf-sync to log in. Update arrconf/userconf.sh or reset the qB WebUI password."
    return
  fi

  stored_user="$(grep -E '^WebUI\\\\Username=' "${cfg}" | head -n1 | cut -d= -f2- || true)"
  if [ -n "${stored_user}" ] && [ "${stored_user}" != "${QBT_USER}" ]; then
    warn "QBT_USER ('${QBT_USER}') does not match qBittorrent WebUI username ('${stored_user}'); pf-sync login will fail until they are aligned."
  fi

  hash_line="$(grep -E '^WebUI\\\\Password_PBKDF2=' "${cfg}" | tail -n1 || true)"
  if [ -z "${hash_line}" ]; then
    warn "Could not find a WebUI password hash in ${cfg}; pf-sync credential verification skipped."
    return
  fi

  if ! check_hash_deps >/dev/null 2>&1; then
    warn "Skipping qBittorrent credential verification (OpenSSL 3 PBKDF2 helpers unavailable)."
    return
  fi

  payload="$(printf '%s\n' "${hash_line}" | sed -E 's/^WebUI\\\\Password_PBKDF2="@ByteArray\(([^"]+)\)"$/\1/' || true)"
  if [ -z "${payload}" ]; then
    warn "Unable to parse qBittorrent password hash from ${cfg}; pf-sync login may fail."
    return
  fi

  salt_b64="${payload%%:*}"
  dk_b64="${payload##*:}"
  if [ -z "${salt_b64}" ] || [ -z "${dk_b64}" ]; then
    warn "Parsed qBittorrent password hash was incomplete; pf-sync login may fail."
    return
  fi

  if command -v xxd >/dev/null 2>&1; then
    salt_hex="$(printf '%s' "${salt_b64}" | base64 -d 2>/dev/null | xxd -p -c 256 | tr -d '\n' || true)"
  else
    salt_hex="$(printf '%s' "${salt_b64}" | base64 -d 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)"
  fi

  if [ -z "${salt_hex}" ]; then
    warn "Failed to decode qBittorrent password salt; pf-sync login verification skipped."
    return
  fi

  derived="$(openssl kdf -binary -keylen 64 \
    -kdfopt digest:SHA512 \
    -kdfopt pass:"${QBT_PASS}" \
    -kdfopt hexsalt:"${salt_hex}" \
    -kdfopt iter:100000 \
    PBKDF2 | base64 | tr -d '\n' || true)"

  if [ -z "${derived}" ]; then
    warn "Failed to derive PBKDF2 hash for qBittorrent credentials; pf-sync login verification skipped."
    return
  fi

  if [ "${derived}" != "${dk_b64}" ]; then
    warn "QBT_PASS does not match the password stored in ${cfg}; pf-sync will be unable to authenticate until they match."
  else
    ok "Verified qBittorrent WebUI credentials for pf-sync login."
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
    image: ${GLUETUN_IMAGE}
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
      SERVER_HOSTNAMES: "${SERVER_HOSTNAMES}"
      # FREE_ONLY: "off"
      # DNS & stability
      DOT: "off"
      UPDATER_PERIOD: ${UPDATER_PERIOD}
      HEALTH_TARGET_ADDRESS: ${GLUETUN_HEALTH_TARGET:-1.1.1.1:443}
      HEALTH_VPN_DURATION_INITIAL: 30s
      HEALTH_SUCCESS_WAIT_DURATION: 10s
      # Control server (RBAC)
      HTTP_CONTROL_SERVER_ADDRESS: "${GLUETUN_CONTROL_LISTEN_ADDR:-127.0.0.1}:${GLUETUN_CONTROL_PORT}"
      HTTP_CONTROL_SERVER_LOG: "off"
      HTTP_CONTROL_SERVER_AUTH_FILE: /gluetun/auth/config.toml
      GLUETUN_API_KEY: ${GLUETUN_API_KEY}
      FIREWALL_OUTBOUND_SUBNETS: "${GLUETUN_FIREWALL_OUTBOUND_SUBNETS}"
      FIREWALL_INPUT_PORTS: "${GLUETUN_FIREWALL_INPUT_PORTS}"
      HTTPPROXY: "${GLUETUN_HTTPPROXY}"
      SHADOWSOCKS: "${GLUETUN_SHADOWSOCKS}"
      PUID: ${PUID}
      PGID: ${PGID}
    volumes:
      - ${ARR_DOCKER_DIR}/gluetun:/gluetun
      - ${ARR_DOCKER_DIR}/gluetun/auth:/gluetun/auth
    ports:
      - "${GLUETUN_CONTROL_BIND_HOST:-127.0.0.1}:${GLUETUN_CONTROL_PORT:-8000}:${GLUETUN_CONTROL_PORT:-8000}"          # Gluetun control API host bind (GLUETUN_CONTROL_BIND_HOST)
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
          curl_with_fallback() {
            URL="$1";
            CODE="000";
            if [ -n "$$AUTH" ]; then
              CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 $$AUTH "$$URL" || echo 000);
              if [ "$$CODE" = "401" ]; then
                AUTH="";
                CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$$URL" || echo 000);
              fi;
            else
              CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$$URL" || echo 000);
            fi;
            if [ "$$CODE" != "200" ]; then
              return 1;
            fi;
            if [ -n "$$AUTH" ]; then
              curl -fsS --max-time 5 $$AUTH "$$URL";
            else
              curl -fsS --max-time 5 "$$URL";
            fi;
          };
          curl_with_fallback "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/publicip/ip" >/dev/null &&
YAML
    if [ "${VPN_TYPE}" = "openvpn" ]; then
      cat <<'YAML'
          curl_with_fallback "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/openvpn/status" | grep -qi "running"
YAML
    else
      cat <<'YAML'
          curl_with_fallback "http://127.0.0.1:${GLUETUN_CONTROL_PORT}/v1/wireguard/status" | grep -Eqi "connected|running"
YAML
    fi
    cat <<'YAML'
        '
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 180s
    restart: unless-stopped

  qbittorrent:
    image: ${QBITTORRENT_IMAGE}
    container_name: qbittorrent
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      WEBUI_PORT: ${QBT_WEBUI_PORT}
      DOCKER_MODS: ${QBT_DOCKER_MODS}
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
      test: ["CMD-SHELL", "ADDR=$(hostname -i 2>/dev/null | awk '{print $1}'); if [ -z \"$ADDR\" ]; then ADDR=127.0.0.1; fi; curl -fsS http://$ADDR:${QBT_WEBUI_PORT}/api/v2/app/version >/dev/null || curl -fsS http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/version >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 6
      start_period: 90s
    restart: unless-stopped

YAML
    if [ "${VPN_TYPE}" = "openvpn" ]; then
      cat <<'YAML'
  pf-sync:
    image: ${PF_SYNC_IMAGE}
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
        LOGIN_STATE="";
        echo "[pf-sync] Waiting for qBittorrent API...";
        until curl -fsS "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/app/version" >/dev/null 2>&1; do
          echo "[pf-sync] qBittorrent not ready yet; retrying in 5s";
          sleep 5;
        done;
        if [ -n "$${QBT_USERNAME}" ] && [ -n "$${QBT_PASSWORD}" ]; then
          echo "[pf-sync] Validating supplied qBittorrent credentials...";
          if curl -fsS -c /tmp/qbt.cookie "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/auth/login" \
            --data "username=$${QBT_USERNAME}&password=$${QBT_PASSWORD}" >/dev/null 2>&1; then
            echo "[pf-sync] qBittorrent login succeeded; authenticated API ready.";
            LOGIN_STATE="auth-ok";
          else
            echo "[pf-sync] WARNING: Initial qBittorrent login failed; pf-sync will keep retrying. Check QBT_USER/QBT_PASS or reset the WebUI password." >&2;
            LOGIN_STATE="auth-fail";
          fi;
          rm -f /tmp/qbt.cookie 2>/dev/null || true;
        else
          echo "[pf-sync] No WebUI credentials provided; relying on local authentication bypass.";
          LOGIN_STATE="anon";
        fi;
        echo "[pf-sync] Requesting Proton forwarded port lease from Gluetun...";
        curl -fsS $${AUTH_HEADER} -X POST "$${API_ROOT}/v1/openvpn/forwardport" >/dev/null 2>&1 || true;
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
                COOKIE=/tmp/qbt.cookie;
                if curl -fsS -c "$$COOKIE" "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/auth/login" \
                  --data "username=$${QBT_USERNAME}&password=$${QBT_PASSWORD}" >/dev/null 2>&1; then
                  if curl -fsS -b "$$COOKIE" \
                    "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/app/setPreferences" \
                    --data "json={\\"listen_port\\":$${P},\\"upnp\\":false}" >/dev/null 2>&1; then
                    CUR="$$P";
                    if [ "$$LOGIN_STATE" != "auth-ok" ]; then
                      echo "[pf-sync] Authenticated qBittorrent API access restored.";
                    fi;
                    LOGIN_STATE="auth-ok";
                  else
                    if [ "$$LOGIN_STATE" != "auth-set-fail" ]; then
                      echo "[pf-sync] ERROR: Authenticated port update request failed; inspect qBittorrent logs." >&2;
                    fi;
                    LOGIN_STATE="auth-set-fail";
                  fi;
                else
                  if [ "$$LOGIN_STATE" != "auth-fail" ]; then
                    echo "[pf-sync] ERROR: qBittorrent login failed for user '$${QBT_USERNAME}'. Verify QBT_USER/QBT_PASS or reset the WebUI password." >&2;
                  fi;
                  LOGIN_STATE="auth-fail";
                fi;
                rm -f "$$COOKIE" 2>/dev/null || true;
              else
                if curl -fsS -X POST \
                  "http://127.0.0.1:$${QBT_WEBUI_PORT}/api/v2/app/setPreferences" \
                  --data "json={\\"listen_port\\":$${P},\\"upnp\\":false}" >/dev/null 2>&1; then
                  CUR="$$P";
                  LOGIN_STATE="anon";
                else
                  if [ "$$LOGIN_STATE" != "anon-fail" ]; then
                    echo "[pf-sync] ERROR: Failed to update qBittorrent listen port without credentials; enable the local auth bypass or set QBT_USER/QBT_PASS." >&2;
                  fi;
                  LOGIN_STATE="anon-fail";
                fi;
              fi;
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
          curl_with_fallback() {
            URL="$1";
            CODE="000";
            if [ -n "$$AUTH" ]; then
              CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 $$AUTH "$$URL" || echo 000);
              if [ "$$CODE" = "401" ]; then
                AUTH="";
                CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$$URL" || echo 000);
              fi;
            else
              CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$$URL" || echo 000);
            fi;
            if [ "$$CODE" != "200" ]; then
              return 1;
            fi;
            if [ -n "$$AUTH" ]; then
              curl -fsS --max-time 5 $$AUTH "$$URL";
            else
              curl -fsS --max-time 5 "$$URL";
            fi;
          };
          curl_with_fallback "http://$${GLUETUN_CONTROL_HOST}:$${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded" | grep -Eq "(^|:)[1-9][0-9]{3,4}$"
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
    image: ${SONARR_IMAGE}
    container_name: sonarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      SONARR__SERVER__BINDADDRESS: "${SONARR_BIND_ADDRESS}"
    volumes:
      - ${ARR_DOCKER_DIR}/sonarr:/config
      - ${TV_DIR}:/tv
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "ADDR=${SONARR_BIND_ADDRESS:-0.0.0.0}; if [ \"$ADDR\" = \"0.0.0.0\" ] || [ \"$ADDR\" = \"*\" ]; then ADDR=$(hostname -i 2>/dev/null | awk '{print $1}'); fi; if [ -z \"$ADDR\" ]; then ADDR=127.0.0.1; fi; curl -fsS http://$ADDR:${SONARR_PORT} >/dev/null || curl -fsS http://127.0.0.1:${SONARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  radarr:
    image: ${RADARR_IMAGE}
    container_name: radarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      RADARR__SERVER__BINDADDRESS: "${RADARR_BIND_ADDRESS}"
    volumes:
      - ${ARR_DOCKER_DIR}/radarr:/config
      - ${MOVIES_DIR}:/movies
      - ${DOWNLOADS_DIR}:/downloads
      - ${COMPLETED_DIR}:/completed
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "ADDR=${RADARR_BIND_ADDRESS:-0.0.0.0}; if [ \"$ADDR\" = \"0.0.0.0\" ] || [ \"$ADDR\" = \"*\" ]; then ADDR=$(hostname -i 2>/dev/null | awk '{print $1}'); fi; if [ -z \"$ADDR\" ]; then ADDR=127.0.0.1; fi; curl -fsS http://$ADDR:${RADARR_PORT} >/dev/null || curl -fsS http://127.0.0.1:${RADARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  prowlarr:
    image: ${PROWLARR_IMAGE}
    container_name: prowlarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      PROWLARR__SERVER__BINDADDRESS: "${PROWLARR_BIND_ADDRESS}"
    volumes:
      - ${ARR_DOCKER_DIR}/prowlarr:/config
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "ADDR=${PROWLARR_BIND_ADDRESS:-0.0.0.0}; if [ \"$ADDR\" = \"0.0.0.0\" ] || [ \"$ADDR\" = \"*\" ]; then ADDR=$(hostname -i 2>/dev/null | awk '{print $1}'); fi; if [ -z \"$ADDR\" ]; then ADDR=127.0.0.1; fi; curl -fsS http://$ADDR:${PROWLARR_PORT} >/dev/null || curl -fsS http://127.0.0.1:${PROWLARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  bazarr:
    image: ${BAZARR_IMAGE}
    container_name: bazarr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      PUID: ${PUID}
      PGID: ${PGID}
      TZ: ${TIMEZONE}
      BAZARR__SERVER__HOST: "${BAZARR_BIND_ADDRESS}"
    volumes:
      - ${ARR_DOCKER_DIR}/bazarr:/config
      - ${TV_DIR}:/tv
      - ${MOVIES_DIR}:/movies
      - ${SUBS_DIR}:/subs
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "ADDR=${BAZARR_BIND_ADDRESS:-0.0.0.0}; if [ \"$ADDR\" = \"0.0.0.0\" ] || [ \"$ADDR\" = \"*\" ]; then ADDR=$(hostname -i 2>/dev/null | awk '{print $1}'); fi; if [ -z \"$ADDR\" ]; then ADDR=127.0.0.1; fi; curl -fsS http://$ADDR:${BAZARR_PORT} >/dev/null || curl -fsS http://127.0.0.1:${BAZARR_PORT} >/dev/null"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    restart: unless-stopped

  flaresolverr:
    image: ${FLARESOLVERR_IMAGE}
    container_name: flaresolverr
    profiles: ["prod"]
    network_mode: "service:gluetun"
    environment:
      LOG_LEVEL: info
    depends_on:
      gluetun:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "ADDR=${ARR_BIND_ADDRESS:-0.0.0.0}; if [ \"$ADDR\" = \"0.0.0.0\" ] || [ \"$ADDR\" = \"*\" ]; then ADDR=$(hostname -i 2>/dev/null | awk '{print $1}'); fi; if [ -z \"$ADDR\" ]; then ADDR=127.0.0.1; fi; curl -fsS http://$ADDR:${FLARESOLVERR_PORT} >/dev/null || curl -fsS http://127.0.0.1:${FLARESOLVERR_PORT} >/dev/null"]
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
wait_for_container_healthy() {
  local container="$1" timeout="${2:-300}" waited=0
  while [[ $waited -lt $timeout ]]; do
    local health
    health="$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo 'unknown')"
    [[ "$health" == "healthy" ]] && return 0
    sleep 5
    waited=$((waited + 5))
  done
  return 1
}

wait_for_vpn_connected() {
  local timeout="${1:-180}" waited=0 ctrl_host ctrl_port endpoint status_pattern
  ctrl_host="$(control_access_host)"
  ctrl_port="${GLUETUN_CONTROL_PORT:-8000}"

  if [[ "${VPN_TYPE}" == "wireguard" ]]; then
    endpoint="/v1/wireguard/status"
    status_pattern="connected|running"
  else
    endpoint="/v1/openvpn/status"
    status_pattern="running"
  fi

  while [[ $waited -lt $timeout ]]; do
    if curl -fsS --max-time 5 -u "gluetun:${GLUETUN_API_KEY}" \
      "http://${ctrl_host}:${ctrl_port}${endpoint}" | grep -Eqi "${status_pattern}"; then
      return 0
    fi
    sleep 10
    waited=$((waited + 10))
  done
  return 1
}

wait_for_port_forwarding() {
  [[ "${VPN_TYPE}" != "openvpn" ]] && return 0

  local timeout="${1:-180}" waited=0 ctrl_host ctrl_port
  ctrl_host="$(control_access_host)"
  ctrl_port="${GLUETUN_CONTROL_PORT:-8000}"

  while [[ $waited -lt $timeout ]]; do
    local pf_raw pf_port
    pf_raw="$(curl -fsS --max-time 5 -u "gluetun:${GLUETUN_API_KEY}" \
      "http://${ctrl_host}:${ctrl_port}/v1/openvpn/portforwarded" 2>/dev/null || true)"
    case "$pf_raw" in
      *:*) pf_port="${pf_raw##*:}" ;;
      *)   pf_port="$pf_raw" ;;
    esac

    if printf '%s' "$pf_port" | grep -Eq '^[1-9][0-9]{3,4}$'; then
      note "Port forwarding ready: $pf_port"
      return 0
    fi

    sleep 15
    waited=$((waited + 15))
  done
  return 1
}

start_with_checks() {
  step "14/15 Starting stack with phased bootstrap"
  validate_creds_or_die
  verify_gluetun_control_security

  bootstrap_fail() {
    local msg="$1"
    {
      echo "=== GLUETUN DIAGNOSTICS ==="
      docker compose ps
      docker logs --tail=50 gluetun
    } >>"$LOG_FILE"
    die "$msg"
  }

  note "Phase 1: Starting Gluetun..."
  compose_cmd up -d gluetun || bootstrap_fail "Failed to start Gluetun"

  note "Phase 2: Waiting for container health..."
  wait_for_container_healthy gluetun 300 || bootstrap_fail "Gluetun container failed health check"

  note "Phase 3: Waiting for VPN connection..."
  wait_for_vpn_connected 180 || bootstrap_fail "VPN connection failed"

  note "Phase 4: Starting dependent services..."
  compose_cmd up -d qbittorrent sonarr radarr prowlarr bazarr flaresolverr || bootstrap_fail "Failed to start services"

  wait_for_container_healthy qbittorrent 90 || warn "qBittorrent health check failed"

  print_qbt_temp_password_if_any
  if [[ -n "${QBT_USER:-}" && -n "${QBT_PASS:-}" ]]; then
    ok "qBittorrent credentials preseeded"
  fi

  run_or_warn compose_cmd ps

  local ctrl_host ctrl_port public_ip
  ctrl_host="$(control_access_host)"
  ctrl_port="${GLUETUN_CONTROL_PORT:-8000}"
  public_ip="$(curl -fsS --max-time 5 -u "gluetun:${GLUETUN_API_KEY}" \
    "http://${ctrl_host}:${ctrl_port}/v1/publicip/ip" 2>/dev/null || true)"
  if [[ -n "$public_ip" ]]; then
    note "Public IP: ${public_ip}"
  else
    warn "Unable to determine public IP"
  fi

  if [[ "${VPN_TYPE}" == "openvpn" ]]; then
    note "Phase 5: Waiting for port forwarding..."
    compose_cmd up -d pf-sync || warn "Failed to start pf-sync"
    wait_for_port_forwarding 180 || warn "Port forwarding not ready"
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
  preflight_gluetun_apikey
  make_gluetun_apikey
  write_gluetun_auth
  write_env
  seed_wireguard_from_conf
  ensure_qbt_conf
  seed_qbt_credentials_if_requested
  verify_qbt_credentials_for_pf_sync
  write_compose
  pull_images
  start_with_checks
  install_aliases
  echo
  ok "Done. Next steps:"
  note "  • Edit ${PROTON_AUTH_FILE} (username WITHOUT +pmp) if you haven't already."
  note "  • qB Web UI: http://${LOCALHOST_NAME}:${QBT_HTTP_PORT_HOST} (use printed admin password or preset QBT_USER/QBT_PASS)."
}

cleanup() {
  local status=$?

  if [[ "${DEBUG}" == "1" && -n "${TMP_LOG:-}" ]]; then
    if [[ -s "${TMP_LOG}" && -n "${DEST_LOG:-}" ]]; then
      local dest_dir move_ok=0
      dest_dir="$(dirname "${DEST_LOG}")"
      if [[ -n "${dest_dir}" ]]; then
        mkdir -p "${dest_dir}" 2>/dev/null || true
      fi
      if mv -f "${TMP_LOG}" "${DEST_LOG}" 2>/dev/null; then
        move_ok=1
      elif cp "${TMP_LOG}" "${DEST_LOG}" 2>/dev/null; then
        rm -f "${TMP_LOG}" 2>/dev/null || true
        move_ok=1
      fi

      if (( move_ok )); then
        chmod 600 "${DEST_LOG}" 2>/dev/null || true
        if [[ -n "${ARR_STACK_DIR:-}" ]]; then
          local pointer base_name
          pointer="${ARR_STACK_DIR%/}/arrstack-install.log"
          base_name="$(basename "${DEST_LOG}")"
          if [[ -n "${base_name}" && "${pointer}" != "${DEST_LOG}" ]]; then
            ln -sfn "${base_name}" "${pointer}" 2>/dev/null || true
          fi
        fi
        printf 'Installer log saved to %s\n' "${DEST_LOG}"
      else
        printf 'Failed to save installer log to %s (temporary log at %s)\n' "${DEST_LOG}" "${TMP_LOG}"
      fi
    else
      if [[ -f "${TMP_LOG}" ]]; then
        rm -f "${TMP_LOG}" 2>/dev/null || true
      fi
    fi
  fi

  exit "${status}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  parse_args "$@"
  setup_logging
  trap cleanup EXIT

  main "$@"
fi
