#!/usr/bin/env bash
set -Euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------
# ARR stack uninstaller / cleanup
# ------------------------------------------------------------
# This script attempts to remove Docker containers, images,
# volumes and native packages related to Sonarr/Radarr/etc.
# All existing configuration and service files are backed up
# to the installer-defined backup tree before removal.
# ------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME="${USER:-$(id -un)}"
ARR_BASE="/home/${USER_NAME}/srv"
ARR_DOCKER_DIR="${ARR_BASE}/docker"
ARR_STACK_DIRS=("${ARR_BASE}/arrstack" "${ARR_BASE}/arr-stack")
ARR_BACKUP_DIR="${ARR_BASE}/backups"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_SUBDIR="${ARR_BACKUP_DIR}/uninstall-${TS}"
ARRCONF_DIR="${REPO_ROOT}/arrconf"
PURGE_ARRCONF=0 # set 1 to remove arrconf secrets

QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8080}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"

SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

ALL_CONTAINERS="gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr jackett transmission lidarr readarr"
ALL_NATIVE_SERVICES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent qbittorrent-nox transmission-daemon transmission-common"
ALL_PACKAGES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent qbittorrent-nox transmission-daemon transmission-common"
CRITICAL_PORTS="${QBT_HTTP_PORT_HOST} ${SONARR_PORT} ${RADARR_PORT} ${PROWLARR_PORT} ${BAZARR_PORT} ${FLARESOLVERR_PORT} ${GLUETUN_CONTROL_PORT}"

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

# ----- logging helpers -------------------------------------------------------
step() { printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_BLUE" "$1" "$C_RESET"; }
note() { printf '%s- %s%s\n' "$C_BLUE" "$1" "$C_RESET"; }
ok() { printf '%s✔ %s%s\n' "$C_GREEN" "$1" "$C_RESET"; }

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

check_prereqs() {
  local cmds=(docker tar find grep awk xargs fuser systemctl dpkg apt-get)
  local cmd
  for cmd in "${cmds[@]}"; do
    require_cmd "$cmd"
  done
  [[ -n "$SUDO" ]] && require_cmd sudo
}

confirm() {
  read -r -p "This will REMOVE Arr stack containers, configs and packages. Continue? (y/N) " ans
  [[ "$ans" =~ ^[Yy]$ ]] || {
    note "Aborted"
    exit 0
  }
}

ensure_dirs() { mkdir -p "${BACKUP_SUBDIR}/systemd"; }

find_app_dirs() {
  local base="$1" depth="${2:-1}" APP
  [[ -d "$base" ]] || return
  for APP in $ALL_CONTAINERS; do
    find "$base" -maxdepth "$depth" -type d -iname "${APP}*" 2>/dev/null
  done
}

system_app_dirs() {
  {
    find_app_dirs /var/lib 1
    find_app_dirs /opt 1
    find_app_dirs /etc 1
  } | sort -u
}

config_file_candidates() {
  find "${HOME}" /etc /var/lib /opt -type f \
    \( -iname 'qBittorrent.conf' -o -iname 'qBittorrent.ini' -o \
    -iname 'settings.json' -o -iname 'config.json' -o \
    -iname 'config.xml' -o -iname 'nzbdrone.db' -o \
    -iname 'sonarr.db' -o -iname 'radarr.db' -o \
    -iname 'prowlarr.db' -o -iname 'bazarr.db' -o \
    -iname 'jackett.db' -o -iname 'lidarr.db' -o \
    -iname 'readarr.db' \) 2>/dev/null
}

backup_all() {
  step "Backing up existing configuration to ${BACKUP_SUBDIR}"
  ensure_dirs
  note "Backing up arrstack directories"
  for d in "${ARR_STACK_DIRS[@]}"; do
    if [[ -d "$d" ]]; then
      tar -C "${ARR_BASE}" -czf "${BACKUP_SUBDIR}/$(basename "$d").tgz" "$(basename "$d")"
    fi
  done
  note "Backing up arrconf directory"
  if [[ -d "${ARRCONF_DIR}" ]]; then
    tar -C "$(dirname "${ARRCONF_DIR}")" -czf "${BACKUP_SUBDIR}/arrconf.tgz" "$(basename "${ARRCONF_DIR}")"
  fi
  note "Backing up docker app configs"
  if [[ -d "${ARR_DOCKER_DIR}" ]]; then
    while IFS= read -r dir; do
      tar -C "$(dirname "$dir")" -czf "${BACKUP_SUBDIR}/docker-$(basename "$dir").tgz" "$(basename "$dir")"
    done < <(find_app_dirs "${ARR_DOCKER_DIR}" 1 | sort -u)
  fi
  note "Backing up home configs"
  while IFS= read -r dir; do
    tar -C "$(dirname "$dir")" -czf "${BACKUP_SUBDIR}/home-$(basename "$dir").tgz" "$(basename "$dir")"
  done < <(find_app_dirs "${HOME}/.config" 1 | sort -u)
  note "Backing up system directories"
  while IFS= read -r dir; do
    $SUDO tar -czf "${BACKUP_SUBDIR}/system-$(basename "$dir").tgz" "$dir" || true
  done < <(system_app_dirs)
  note "Backing up systemd service files"
  for SVC in ${ALL_NATIVE_SERVICES}; do
    for DIR in /etc/systemd/system /lib/systemd/system; do
      if [[ -f "${DIR}/${SVC}.service" ]]; then
        $SUDO cp "${DIR}/${SVC}.service" "${BACKUP_SUBDIR}/systemd/${SVC}.service"
      fi
    done
  done
  note "Backing up standalone config files"
  mkdir -p "${BACKUP_SUBDIR}/files"
  while IFS= read -r file; do
    $SUDO cp --parents "$file" "${BACKUP_SUBDIR}/files" 2>/dev/null || true
  done < <(config_file_candidates)
  ok "Backups saved to ${BACKUP_SUBDIR}"
}

stop_stack() {
  step "Stopping Docker stack"
  for d in "${ARR_STACK_DIRS[@]}"; do
    if [[ -d "$d" ]]; then
      (cd "$d" && docker compose down -v --remove-orphans) || true
    fi
  done
  for c in ${ALL_CONTAINERS}; do
    if docker ps -a --format '{{.Names}}' | grep -qF "${c}"; then
      docker rm -f "${c}" >/dev/null 2>&1 || true
    fi
  done
  docker volume ls -q | grep -Ei '(^|_)(sonarr|radarr|prowlarr|bazarr|jackett|lidarr|readarr|qbittorrent|transmission|gluetun|flaresolverr)' | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker images --format '{{.Repository}} {{.ID}}' | grep -Ei 'qbittorrent|sonarr|radarr|prowlarr|bazarr|jackett|lidarr|readarr|gluetun|flaresolverr|transmission' | awk '{print $2}' | xargs -r docker rmi -f >/dev/null 2>&1 || true
  for p in ${CRITICAL_PORTS}; do
    if $SUDO fuser "${p}/tcp" >/dev/null 2>&1; then
      warn "Killing process on port ${p}"
      $SUDO fuser -k "${p}/tcp" >/dev/null 2>&1 || true
    fi
  done
  ok "Docker cleanup complete"
}

remove_native() {
  step "Removing native services and packages"
  for SVC in ${ALL_NATIVE_SERVICES}; do
    if systemctl list-units --all --type=service | grep -q "${SVC}.service"; then
      note "Stopping ${SVC}"
      $SUDO systemctl stop "${SVC}" >/dev/null 2>&1 || true
      $SUDO systemctl disable "${SVC}" >/dev/null 2>&1 || true
      $SUDO systemctl mask "${SVC}" >/dev/null 2>&1 || true
    fi
    $SUDO rm -f "/etc/systemd/system/${SVC}.service" "/lib/systemd/system/${SVC}.service" 2>/dev/null || true
  done
  $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
  note "Purging packages"
  $SUDO apt-get update -y >/dev/null 2>&1 || true
  for PKG in ${ALL_PACKAGES}; do
    if dpkg -l | grep -q "^ii.*${PKG}"; then
      $SUDO apt-get purge -y "${PKG}" >/dev/null 2>&1 || true
    fi
  done
  $SUDO apt-get autoremove -y >/dev/null 2>&1 || true
  ok "Native packages removed"
}

remove_files() {
  step "Removing residual files"
  for d in "${ARR_STACK_DIRS[@]}" "${ARR_DOCKER_DIR}"; do
    $SUDO rm -rf "$d" 2>/dev/null || true
  done
  while IFS= read -r dir; do
    rm -rf "$dir" 2>/dev/null || true
  done < <(find_app_dirs "${HOME}/.config" 1 | sort -u)
  while IFS= read -r dir; do
    $SUDO rm -rf "$dir" 2>/dev/null || true
  done < <(system_app_dirs)
  while IFS= read -r file; do
    $SUDO rm -f "$file" 2>/dev/null || true
  done < <(config_file_candidates)
  ok "File cleanup complete"
}

purge_arrconf() {
  [[ "$PURGE_ARRCONF" -eq 1 ]] || return 0
  [[ -d "$ARRCONF_DIR" ]] || return 0
  read -r -p "Purge arrconf (secrets) directory? (y/N) " ans
  [[ $ans =~ ^[Yy]$ ]] || {
    note "Kept ${ARRCONF_DIR}"
    return 0
  }
  mkdir -p "${BACKUP_SUBDIR}"
  if [[ ! -f "${BACKUP_SUBDIR}/arrconf.tgz" ]]; then
    tar -C "$(dirname "$ARRCONF_DIR")" -czf "${BACKUP_SUBDIR}/arrconf.tgz" "$(basename "$ARRCONF_DIR")"
  fi
  rm -rf "$ARRCONF_DIR"
  ok "Purged arrconf (backup at ${BACKUP_SUBDIR}/arrconf.tgz)"
}

main() {
  for a in "$@"; do
    [[ $a == "--purge-arrconf" ]] && PURGE_ARRCONF=1
  done
  check_prereqs
  confirm
  backup_all
  stop_stack
  remove_native
  remove_files
  purge_arrconf
  step "Done. Backups stored at ${BACKUP_SUBDIR}"
}

main "$@"
