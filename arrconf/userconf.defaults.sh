# shellcheck shell=bash
# arrconf/userconf.defaults.sh — tracked defaults (safe to update from repo)
# Example defaults — keep in sync with README
# NOTE: Paths outside your home directory must exist with correct permissions.

# User and base directories
USER_NAME="${USER_NAME:-${USER:-$(id -un)}}"
ARR_BASE="${ARR_BASE:-/home/${USER_NAME}/srv}"
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-${ARR_BASE}/docker}"
ARR_STACK_DIR="${ARR_STACK_DIR:-${ARR_BASE}/arrstack}"
ARR_BACKUP_DIR="${ARR_BACKUP_DIR:-${ARR_BASE}/backups}"
ARRCONF_DIR="${ARRCONF_DIR:-${REPO_ROOT}/arrconf}"
ARR_ENV_FILE="${ARR_ENV_FILE:-${ARR_STACK_DIR}/.env}"

# Legacy secrets paths (for backward compatibility)
LEGACY_VPNCONFS_DIR="${LEGACY_VPNCONFS_DIR:-${ARR_BASE}/wg-configs}"
LEGACY_CREDS_DOCKER="${LEGACY_CREDS_DOCKER:-${ARR_DOCKER_DIR}/gluetun/proton-credentials.conf}"
LEGACY_CREDS_WG="${LEGACY_CREDS_WG:-${LEGACY_VPNCONFS_DIR}/proton-credentials.conf}"

# Local network binding settings
LAN_IP="${LAN_IP:-192.168.1.11}"
LOCALHOST_ADDR="${LOCALHOST_ADDR:-127.0.0.1}"
LOCALHOST_NAME="${LOCALHOST_NAME:-localhost}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
GLUETUN_CONTROL_HOST="${GLUETUN_CONTROL_HOST:-${LOCALHOST_ADDR}}"
GLUETUN_CONTROL_HOST_BIND="${GLUETUN_CONTROL_HOST_BIND:-127.0.0.1}"
GLUETUN_CONTROL_LISTEN_IP="${GLUETUN_CONTROL_LISTEN_IP:-127.0.0.1}"
GLUETUN_CONTROL_SERVER_ADDRESS="${GLUETUN_CONTROL_SERVER_ADDRESS:-}"
GLUETUN_HEALTH_TARGET="${GLUETUN_HEALTH_TARGET:-1.1.1.1:443}"
UPDATER_PERIOD="${UPDATER_PERIOD:-24h}"

# Media and download paths
MEDIA_DIR="${MEDIA_DIR:-/media/arrs}"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-/home/${USER_NAME}/Downloads}"
COMPLETED_DIR="${COMPLETED_DIR:-${DOWNLOADS_DIR}/completed}"
MOVIES_DIR="${MOVIES_DIR:-${MEDIA_DIR}/movies}"
TV_DIR="${TV_DIR:-${MEDIA_DIR}/shows}"
SUBS_DIR="${SUBS_DIR:-${MEDIA_DIR}/subs}"

# qBittorrent Web UI credentials and paths
QBT_WEBUI_PORT="${QBT_WEBUI_PORT:-8080}"
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8081}"
QBT_USER="${QBT_USER:-}"
QBT_PASS="${QBT_PASS:-}"
QBT_SAVE_PATH="${QBT_SAVE_PATH:-/completed/}"
QBT_TEMP_PATH="${QBT_TEMP_PATH:-/downloads/incomplete/}"
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"

# Service ports for core apps
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

# Container user identity and timezone
PUID="${PUID:-$(id -u)}"
PGID="${PGID:-$(id -g)}"
TIMEZONE="${TIMEZONE:-Australia/Sydney}"

# ProtonVPN defaults and selection
PROTON_AUTH_FILE="${PROTON_AUTH_FILE:-${ARRCONF_DIR}/proton.auth}"
DEFAULT_VPN_TYPE="${DEFAULT_VPN_TYPE:-openvpn}"
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Netherlands,Germany,Switzerland}"
DEFAULT_COUNTRY="${DEFAULT_COUNTRY:-Australia}"

# Service/package lists used by uninstaller
ALL_CONTAINERS="${ALL_CONTAINERS:-gluetun qbittorrent pf-sync sonarr radarr prowlarr bazarr flaresolverr jackett transmission lidarr readarr byparr}"
ALL_NATIVE_SERVICES="${ALL_NATIVE_SERVICES:-sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common byparr}"
ALL_PACKAGES="${ALL_PACKAGES:-sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common byparr}"

# Runtime flags controlling script behaviour
DRY_RUN="${DRY_RUN:-0}"
DEBUG="${DEBUG:-0}"
NO_COLOR="${NO_COLOR:-0}"
VPN_TYPE="${VPN_TYPE:-${VPN_MODE:-${DEFAULT_VPN_TYPE}}}"
