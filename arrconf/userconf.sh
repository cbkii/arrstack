# shellcheck shell=bash
# Optional user overrides for arrstack.
# Uncomment and edit settings below to override defaults from arrstack.sh.

# USER_NAME="${USER:-$(id -un)}"
# ARR_BASE="/home/${USER_NAME}/srv"
# ARR_DOCKER_DIR="${ARR_BASE}/docker"
# ARR_STACK_DIR="${ARR_BASE}/arrstack"
# ARR_BACKUP_DIR="${ARR_BASE}/backups"
# ARRCONF_DIR="${REPO_ROOT}/arrconf"

# Legacy secrets paths (auto-migrated on first run)
# LEGACY_VPNCONFS_DIR="${ARR_BASE}/wg-configs"     # legacy Proton WG config directory
# LEGACY_CREDS_DOCKER="${ARR_DOCKER_DIR}/gluetun/proton-credentials.conf" # legacy OpenVPN creds
# LEGACY_CREDS_WG="${LEGACY_VPNCONFS_DIR}/proton-credentials.conf"         # legacy WG creds

# Local IP for binding services
# LAN_IP="192.168.1.50" # set to your host's LAN IP
# GLUETUN_CONTROL_PORT="8000" # Gluetun control server port
# GLUETUN_CONTROL_HOST="127.0.0.1" # Host used for Gluetun control server checks

# Media/Downloads layout
# MEDIA_DIR="/media/mediasmb"
# DOWNLOADS_DIR="/home/${USER_NAME}/downloads"
# COMPLETED_DIR="${DOWNLOADS_DIR}/completed"
# MOVIES_DIR="${MEDIA_DIR}/Movies"
# TV_DIR="${MEDIA_DIR}/Shows"
# SUBS_DIR="${MEDIA_DIR}/subs"

# qBittorrent UI credentials/ports
# QBT_WEBUI_PORT="8080"     # qBittorrent WebUI port inside container
# QBT_HTTP_PORT_HOST="8080" # host port mapped to qBittorrent
# QBT_USER=""
# QBT_PASS=""
# GLUETUN_API_KEY=""

# Service ports (host:container)
# SONARR_PORT="8989"
# RADARR_PORT="7878"
# PROWLARR_PORT="9696"
# BAZARR_PORT="6767"
# FLARESOLVERR_PORT="8191"

# Identity & timezone
# PUID="$(id -u)"
# PGID="$(id -g)"
# TIMEZONE="Australia/Sydney"

# Proton defaults and selection
# PROTON_AUTH_FILE="${ARRCONF_DIR}/proton.auth"
# DEFAULT_VPN_MODE="openvpn" # openvpn (preferred) | wireguard (fallback)
# SERVER_COUNTRIES="Netherlands,Germany,Switzerland,Australia,Spain,United States"
# DEFAULT_COUNTRY="Australia"

# Service/package lists (kept at least as broad as originals)
# ALL_CONTAINERS="gluetun qbittorrent sonarr radarr prowlarr bazarr flaresolverr jackett transmission lidarr readarr"
# ALL_NATIVE_SERVICES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common"
# ALL_PACKAGES="sonarr radarr prowlarr bazarr jackett lidarr readarr qbittorrent transmission-daemon transmission-common"

# Runtime flags
# DRY_RUN="${DRY_RUN:-0}"
# DEBUG="${DEBUG:-0}"
# NO_COLOR="${NO_COLOR:-0}"
# VPN_MODE="${DEFAULT_VPN_MODE}"

# Critical host ports we may free up
# CRITICAL_PORTS="${QBT_HTTP_PORT_HOST} ${SONARR_PORT} ${RADARR_PORT} ${PROWLARR_PORT} ${BAZARR_PORT} ${FLARESOLVERR_PORT} ${GLUETUN_CONTROL_PORT}"
