#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# ARR stack uninstaller / cleanup
# ------------------------------------------------------------
# This script attempts to remove Docker containers, images,
# volumes and native packages related to Sonarr/Radarr/etc.
# All existing configuration and service files are backed up
# to ~/arrs-bak/DATE/ before removal.
# ------------------------------------------------------------

USER_NAME="${USER:-$(id -un)}"
HOME_DIR="/home/${USER_NAME}"
ARR_BASE="${HOME_DIR}/srv"
ARR_STACK_DIR="${ARR_BASE}/arr-stack"
ARR_DOCKER_DIR="${ARR_BASE}/docker"
BACKUP_ROOT="${HOME_DIR}/arrs-bak"
TS="$(date +%Y%m%d-%H%M%S)"
BAK_DIR="${BACKUP_ROOT}/${TS}"

APPS="qbittorrent sonarr radarr prowlarr bazarr jackett lidarr readarr transmission gluetun flaresolverr"
NATIVE_SERVICES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent qbittorrent-nox transmission-daemon"
NATIVE_PACKAGES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent qbittorrent-nox transmission-daemon transmission-common"
CRITICAL_PORTS="8080 8989 7878 9696 6767 8191 8000"

# ----- logging helpers -------------------------------------------------------
step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
note() { printf '\033[0;36m- %s\033[0m\n' "$1"; }
ok()   { printf '\033[0;32m✔ %s\033[0m\n' "$1"; }
warn() { printf '\033[0;33m⚠ %s\033[0m\n' "$1"; }

SUDO=""
[[ $EUID -ne 0 ]] && SUDO="sudo"

confirm() {
  read -r -p "This will REMOVE Arr stack containers, configs and packages. Continue? (y/N) " ans
  [[ $ans =~ ^[Yy]$ ]] || { note "Aborted"; exit 0; }
}

ensure_dirs() { mkdir -p "${BAK_DIR}/systemd"; }

find_app_dirs() {
  local base=$1 depth=${2:-1} APP
  [[ -d $base ]] || return
  for APP in $APPS; do
    find "$base" -maxdepth "$depth" -type d -iname "${APP}*" 2>/dev/null
  done
}

backup_all() {
  step "Backing up existing configuration to ${BAK_DIR}"
  ensure_dirs
  note "Backing up arr-stack directory"
  if [[ -d "${ARR_STACK_DIR}" ]]; then
    tar -C "${ARR_BASE}" -czf "${BAK_DIR}/arr-stack.tgz" "arr-stack"
  fi
  note "Backing up docker app configs"
  if [[ -d "${ARR_DOCKER_DIR}" ]]; then
    while IFS= read -r dir; do
      tar -C "$(dirname "$dir")" -czf "${BAK_DIR}/docker-$(basename "$dir").tgz" "$(basename "$dir")"
    done < <(find_app_dirs "${ARR_DOCKER_DIR}" 1 | sort -u)
  fi
  note "Backing up home configs"
  while IFS= read -r dir; do
    tar -C "$(dirname "$dir")" -czf "${BAK_DIR}/home-$(basename "$dir").tgz" "$(basename "$dir")"
  done < <(find_app_dirs "${HOME_DIR}/.config" 1 | sort -u)
  note "Backing up system directories"
  while IFS= read -r dir; do
    $SUDO tar -czf "${BAK_DIR}/system-$(basename "$dir").tgz" "$dir" || true
  done < <(
    {
      find_app_dirs /var/lib 1
      find_app_dirs /opt 1
      find_app_dirs /etc 1
    } | sort -u
  )
  note "Backing up systemd service files"
  for SVC in ${NATIVE_SERVICES}; do
    for DIR in /etc/systemd/system /lib/systemd/system; do
      if [[ -f "${DIR}/${SVC}.service" ]]; then
        $SUDO cp "${DIR}/${SVC}.service" "${BAK_DIR}/systemd/${SVC}.service"
      fi
    done
  done
  note "Backing up standalone config files"
  while IFS= read -r file; do
    mkdir -p "${BAK_DIR}/files"
    $SUDO cp --parents "$file" "${BAK_DIR}/files" 2>/dev/null || true
  done < <(
    find "${HOME_DIR}" /etc /var/lib /opt -type f \
      \( -iname 'qBittorrent.conf' -o -iname 'qBittorrent.ini' -o \
         -iname 'settings.json' -o -iname 'config.json' -o \
         -iname 'config.xml' -o -iname 'nzbdrone.db' -o \
         -iname 'sonarr.db' -o -iname 'radarr.db' -o \
         -iname 'prowlarr.db' -o -iname 'bazarr.db' -o \
         -iname 'jackett.db' -o -iname 'lidarr.db' -o \
         -iname 'readarr.db' \) 2>/dev/null
  )
  ok "Backups saved to ${BAK_DIR}"
}

stop_stack() {
  step "Stopping Docker stack"
  if [[ -d "${ARR_STACK_DIR}" ]]; then
    ( cd "${ARR_STACK_DIR}" && docker compose down -v --remove-orphans >/dev/null 2>&1 ) || true
  fi
  for c in ${APPS}; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
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
  for SVC in ${NATIVE_SERVICES}; do
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
  for PKG in ${NATIVE_PACKAGES}; do
    if dpkg -l | grep -q "^ii.*${PKG}"; then
      $SUDO apt-get purge -y "${PKG}" >/dev/null 2>&1 || true
    fi
  done
  $SUDO apt-get autoremove -y >/dev/null 2>&1 || true
  ok "Native packages removed"
}

remove_files() {
  step "Removing residual files"
  $SUDO rm -rf "${ARR_STACK_DIR}" "${ARR_DOCKER_DIR}" 2>/dev/null || true
  while IFS= read -r dir; do
    rm -rf "$dir" 2>/dev/null || true
  done < <(find_app_dirs "${HOME_DIR}/.config" 1 | sort -u)
  while IFS= read -r dir; do
    $SUDO rm -rf "$dir" 2>/dev/null || true
  done < <(
    {
      find_app_dirs /var/lib 1
      find_app_dirs /opt 1
      find_app_dirs /etc 1
    } | sort -u
  )
  while IFS= read -r file; do
    $SUDO rm -f "$file" 2>/dev/null || true
  done < <(
    find "${HOME_DIR}" /etc /var/lib /opt -type f \
      \( -iname 'qBittorrent.conf' -o -iname 'qBittorrent.ini' -o \
         -iname 'settings.json' -o -iname 'config.json' -o \
         -iname 'config.xml' -o -iname 'nzbdrone.db' -o \
         -iname 'sonarr.db' -o -iname 'radarr.db' -o \
         -iname 'prowlarr.db' -o -iname 'bazarr.db' -o \
         -iname 'jackett.db' -o -iname 'lidarr.db' -o \
         -iname 'readarr.db' \) 2>/dev/null
  )
  ok "File cleanup complete"
}

main() {
  confirm
  backup_all
  stop_stack
  remove_native
  remove_files
  step "Done. Backups stored at ${BAK_DIR}"
}

main "$@"
