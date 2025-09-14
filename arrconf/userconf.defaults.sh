# shellcheck shell=bash
# arrconf/userconf.defaults.sh — tracked defaults (safe to update from repo)
# Example defaults — keep in sync with README

USER_NAME="${USER_NAME:-${USER:-$(id -un)}}"
ARR_BASE="${ARR_BASE:-/home/${USER_NAME}/srv}"
ARR_DOCKER_DIR="${ARR_DOCKER_DIR:-${ARR_BASE}/docker}"
ARR_STACK_DIR="${ARR_STACK_DIR:-${ARR_BASE}/arrstack}"
ARR_BACKUP_DIR="${ARR_BACKUP_DIR:-${ARR_BASE}/backups}"
ARRCONF_DIR="${ARRCONF_DIR:-${REPO_ROOT}/arrconf}"

# Legacy secrets paths
LEGACY_VPNCONFS_DIR="${LEGACY_VPNCONFS_DIR:-${ARR_BASE}/wg-configs}"
LEGACY_CREDS_DOCKER="${LEGACY_CREDS_DOCKER:-${ARR_DOCKER_DIR}/gluetun/proton-credentials.conf}"
LEGACY_CREDS_WG="${LEGACY_CREDS_WG:-${LEGACY_VPNCONFS_DIR}/proton-credentials.conf}"

# Local IP for binding services
LAN_IP="${LAN_IP:-192.168.1.50}"
GLUETUN_CONTROL_PORT="${GLUETUN_CONTROL_PORT:-8000}"
GLUETUN_CONTROL_HOST="${GLUETUN_CONTROL_HOST:-127.0.0.1}"
GLUETUN_HEALTH_TARGET="${GLUETUN_HEALTH_TARGET:-1.1.1.1:443}"

# Media/Downloads layout
MEDIA_DIR="${MEDIA_DIR:-/media/mediasmb}"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-/home/${USER_NAME}/downloads}"
COMPLETED_DIR="${COMPLETED_DIR:-${DOWNLOADS_DIR}/completed}"
MOVIES_DIR="${MOVIES_DIR:-${MEDIA_DIR}/Movies}"
TV_DIR="${TV_DIR:-${MEDIA_DIR}/Shows}"
SUBS_DIR="${SUBS_DIR:-${MEDIA_DIR}/subs}"

# qBittorrent UI credentials/ports
QBT_WEBUI_PORT="${QBT_WEBUI_PORT:-8080}"
QBT_HTTP_PORT_HOST="${QBT_HTTP_PORT_HOST:-8080}"
QBT_USER="${QBT_USER:-}"
QBT_PASS="${QBT_PASS:-}"
QBT_SAVE_PATH="${QBT_SAVE_PATH:-/completed/}"
QBT_TEMP_PATH="${QBT_TEMP_PATH:-/downloads/incomplete/}"
GLUETUN_API_KEY="${GLUETUN_API_KEY:-}"

# Service ports
SONARR_PORT="${SONARR_PORT:-8989}"
RADARR_PORT="${RADARR_PORT:-7878}"
PROWLARR_PORT="${PROWLARR_PORT:-9696}"
BAZARR_PORT="${BAZARR_PORT:-6767}"
FLARESOLVERR_PORT="${FLARESOLVERR_PORT:-8191}"

# Identity & timezone
PUID="${PUID:-$(id -u)}"
PGID="${PGID:-$(id -g)}"
TIMEZONE="${TIMEZONE:-Australia/Sydney}"

# Proton defaults and selection
PROTON_AUTH_FILE="${PROTON_AUTH_FILE:-${ARRCONF_DIR}/proton.auth}"
DEFAULT_VPN_MODE="${DEFAULT_VPN_MODE:-openvpn}"
SERVER_COUNTRIES="${SERVER_COUNTRIES:-Switzerland,Iceland,Sweden,Netherlands}"
SERVER_CC_PRIORITY="${SERVER_CC_PRIORITY:-Australia,Singapore,Japan,Hong Kong,United States,United Kingdom,Netherlands,Germany,Switzerland,Spain,Romania,Luxembourg}"
DEFAULT_COUNTRY="${DEFAULT_COUNTRY:-Australia}"

# Service/package lists
ALL_CONTAINERS="${ALL_CONTAINERS:-gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr jackett transmission lidarr readarr}"
ALL_NATIVE_SERVICES="${ALL_NATIVE_SERVICES:-sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common}"
ALL_PACKAGES="${ALL_PACKAGES:-sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common}"

# Runtime flags
DRY_RUN="${DRY_RUN:-0}"
DEBUG="${DEBUG:-0}"
NO_COLOR="${NO_COLOR:-0}"
VPN_MODE="${VPN_MODE:-${DEFAULT_VPN_MODE}}"
