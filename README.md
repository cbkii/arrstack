# arrstack

### 1) Overview
- Installs Gluetun (ProtonVPN provider), qBittorrent, Sonarr, Radarr, Prowlarr, Bazarr, and FlareSolverr with Proton port forwarding managed by a pf-sync sidecar in OpenVPN mode.
- WireGuard is optional; the stack still launches through Gluetun but Proton port forwarding does not apply in that mode.

### 2) Prerequisites
- Debian/Ubuntu host with `sudo`; the installer installs any missing `docker.io`, `docker-compose-plugin`, `curl`, `iproute2`, `openssl`, and `xxd` packages and requires Docker Compose v2.
- ProtonVPN Plus/Unlimited account:
  - OpenVPN: populate `arrconf/proton.auth` with `PROTON_USER`/`PROTON_PASS` (username **without** `+pmp`).
  - WireGuard: place `proton.conf` (or `wg*.conf`) in `${ARRCONF_DIR}`, `${ARR_DOCKER_DIR}/gluetun`, or `${LEGACY_VPNCONFS_DIR}`.
- Filesystem: ensure directories referenced in `arrconf/userconf.defaults.sh` (or overrides in `arrconf/userconf.sh`) exist and are writable before running.
- Ports: free the values mapped to `${GLUETUN_CONTROL_PORT}`, `${QBT_HTTP_PORT_HOST}`, `${SONARR_PORT}`, `${RADARR_PORT}`, `${PROWLARR_PORT}`, `${BAZARR_PORT}`, and `${FLARESOLVERR_PORT}`.
- LAN binding: set `LAN_IP` to your LAN adapter for restricted exposure to the web UIs. The Gluetun control API now binds to loopback via `GLUETUN_CONTROL_HOST_BIND=127.0.0.1`; override only if remote control is required.

### 3) Quick start
**OpenVPN + Proton PF**
```bash
cp arrconf/userconf.defaults.sh arrconf/userconf.sh  # optional overrides
nano arrconf/userconf.sh                              # adjust paths, LAN_IP, ports (optional)
./arrstack.sh --openvpn --yes
# Web UI: http://${LOCALHOST_NAME:-localhost}:${QBT_HTTP_PORT_HOST}
```

**WireGuard (no Proton PF)**
```bash
# place proton.conf (or wg*.conf) in arrconf/ or a legacy search path first
./arrstack.sh --wireguard --yes
# Web UI: http://${LOCALHOST_NAME:-localhost}:${QBT_HTTP_PORT_HOST}
```
Both modes prompt for nothing when `--yes` is used; credentials and secrets are sourced from `arrconf/` and `.env`.

### 4) Flags (CLI)
| Flag | Meaning |
| ---- | ------- |
| `--openvpn` | Force `VPN_TYPE=openvpn` (enables Proton port forwarding workflow). |
| `--wireguard` | Force `VPN_TYPE=wireguard` (skips PF sync). |
| `--debug` | Persist installer logs under `${ARR_STACK_DIR}` (mode `0600`). |
| `-y`, `--yes` | Non-interactive install and implicit proceed confirmation. |
| `--no-prompt`, `--non-interactive` | Equivalent to `--yes`; set `ARR_NONINTERACTIVE=1` without showing prompts. |
| `--rotate-apikey`, `--rotate-api-key`, `--rotate-key` | Force generation of a fresh `GLUETUN_API_KEY`. |

Additional command:
- `./arrstack.sh conf-diff` – compare `arrconf/userconf.sh` overrides to the tracked defaults.

### 5) Environment variables
| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `ARR_BASE` | `/home/$USER/srv` | Root for stack data, backups, and docker configs. |
| `ARR_STACK_DIR` | `${ARR_BASE}/arrstack` | Installer outputs (`.env`, compose file, logs) and log storage. |
| `ARR_DOCKER_DIR` | `${ARR_BASE}/docker` | Per-service configuration volume mounts (e.g., `gluetun`, `qbittorrent`). |
| `ARRCONF_DIR` | `${REPO_ROOT}/arrconf` | Secrets and overrides directory; enforced `700/600` permissions. |
| `ARR_ENV_FILE` | `${ARR_STACK_DIR}/.env` | Generated Compose environment file consumed by the installer and docker compose. |
| `LAN_IP` | `192.168.1.11` | Host bind for *arr/qBittorrent ports; `0.0.0.0` exposes every interface. |
| `LOCALHOST_ADDR` / `LOCALHOST_NAME` | `127.0.0.1` / `localhost` | Default client host for Gluetun API and UI URLs. |
| `GLUETUN_CONTROL_PORT` | `8000` | Gluetun control API port; mapped via `${GLUETUN_CONTROL_HOST_BIND}` and guarded by RBAC. |
| `GLUETUN_CONTROL_HOST_BIND` | `127.0.0.1` | Host interface published for the control API; keep loopback unless you front it securely. |
| `GLUETUN_CONTROL_LISTEN_IP` | `127.0.0.1` | Container-side listener used to build `HTTP_CONTROL_SERVER_ADDRESS`. |
| `HTTP_CONTROL_SERVER_ADDRESS` | `127.0.0.1:8000` | Full container listen address for the control API; override if you need a custom Gluetun binding. |
| `QBT_WEBUI_PORT` / `QBT_HTTP_PORT_HOST` | `8080` / `8081` | Internal and host ports for the qBittorrent Web UI. |
| `MEDIA_DIR`, `DOWNLOADS_DIR`, `COMPLETED_DIR`, `MOVIES_DIR`, `TV_DIR`, `SUBS_DIR` | See defaults | Bind mounts for media and download libraries. |
| `PUID` / `PGID` | Current user/group | Container runtime user identity. |
| `TIMEZONE` | `Australia/Sydney` | Propagated to containers. |
| `SERVER_COUNTRIES` | `Netherlands,Germany,Switzerland` | Gluetun server selection list for ProtonVPN. |
| `UPDATER_PERIOD` | `24h` | Gluetun server list refresh interval (`0` disables updates). |
| `PROTON_AUTH_FILE` | `${ARRCONF_DIR}/proton.auth` | Location of Proton credentials template (600 permissions). |
| `VPN_TYPE` / `DEFAULT_VPN_TYPE` | `openvpn` | Active VPN mode; defaults can be overridden for unattended runs. |
| `QBT_USER` / `QBT_PASS` | empty | Optional Web UI credentials pre-seeded when hashing dependencies exist. |
| `GLUETUN_API_KEY` | generated | Control API RBAC secret written to `.env` and `gluetun/auth/config.toml`. |
| `DEBUG` | `0` | When `1`, keeps installer logs (`--debug` sets this automatically). |

#### Ports (host → container)

All service bindings honour `LAN_IP` except the Gluetun control API, which uses `GLUETUN_CONTROL_HOST_BIND`. Keep these on RFC1918 addresses unless you intend to expose the stack broadly.

| Service | Host port | Container endpoint | Controlled by |
| ------- | --------- | ------------------ | ------------- |
| Gluetun control API | `${GLUETUN_CONTROL_HOST_BIND}:${GLUETUN_CONTROL_PORT}` | `${HTTP_CONTROL_SERVER_ADDRESS}` | `GLUETUN_CONTROL_HOST_BIND` / `GLUETUN_CONTROL_PORT` |
| qBittorrent Web UI | `${LAN_IP}:${QBT_HTTP_PORT_HOST}` | `qbittorrent:${QBT_WEBUI_PORT}` | `QBT_HTTP_PORT_HOST` / `QBT_WEBUI_PORT` |
| Sonarr | `${LAN_IP}:${SONARR_PORT}` | `sonarr:${SONARR_PORT}` | `SONARR_PORT` |
| Radarr | `${LAN_IP}:${RADARR_PORT}` | `radarr:${RADARR_PORT}` | `RADARR_PORT` |
| Prowlarr | `${LAN_IP}:${PROWLARR_PORT}` | `prowlarr:${PROWLARR_PORT}` | `PROWLARR_PORT` |
| Bazarr | `${LAN_IP}:${BAZARR_PORT}` | `bazarr:${BAZARR_PORT}` | `BAZARR_PORT` |
| FlareSolverr | `${LAN_IP}:${FLARESOLVERR_PORT}` | `flaresolverr:${FLARESOLVERR_PORT}` | `FLARESOLVERR_PORT` |

#### Default directories & mounts

The installer creates these paths if they do not exist; adjust overrides in `arrconf/userconf.sh` before running.

| Host directory | Container mount | Purpose / notes |
| -------------- | ---------------- | --------------- |
| `${ARR_STACK_DIR}` | n/a | Holds `.env`, `docker-compose.yml`, and saved logs. |
| `${ARR_DOCKER_DIR}/gluetun` | `/gluetun` | Gluetun state, including WireGuard exports. |
| `${ARR_DOCKER_DIR}/gluetun/auth` | `/gluetun/auth` | RBAC config (`config.toml`) for the control API. |
| `${ARR_DOCKER_DIR}/qbittorrent` | `/config` | qBittorrent configuration (Vuetorrent mod included). |
| `${DOWNLOADS_DIR}` | `/downloads` | Active downloads visible to qBittorrent and the *arr apps. |
| `${COMPLETED_DIR}` | `/completed` | Completed torrents; qBittorrent and Sonarr/Radarr monitor this path. |
| `${ARR_DOCKER_DIR}/sonarr` | `/config` | Sonarr configuration. |
| `${ARR_DOCKER_DIR}/radarr` | `/config` | Radarr configuration. |
| `${ARR_DOCKER_DIR}/prowlarr` | `/config` | Prowlarr configuration. |
| `${ARR_DOCKER_DIR}/bazarr` | `/config` | Bazarr configuration. |
| `${TV_DIR}` | `/tv` | Shared TV library mount (Sonarr, Bazarr). |
| `${MOVIES_DIR}` | `/movies` | Shared movie library mount (Radarr, Bazarr). |
| `${SUBS_DIR}` | `/subs` | Subtitle library for Bazarr. |

> Advanced and legacy variables (e.g., `LEGACY_VPNCONFS_DIR`, `DRY_RUN`) are documented in `arrconf/userconf.defaults.sh`.

### 6) What the installer does (high-level)
1. Runs preflight checks: loads defaults/overrides, validates Proton secrets or WireGuard configs, resolves `LAN_IP`, and confirms the run unless `--yes` is set.
2. Verifies/installs dependencies, then stops any existing containers, frees critical ports, halts native services, backs up data, and purges conflicting packages.
3. Creates directory structure, tightens `arrconf/` permissions, migrates legacy Proton secrets, and ensures Proton auth files exist with `600` mode.
4. Handles Gluetun API key reuse or rotation, writes RBAC config, and generates the `.env` plus Proton credentials/WireGuard variables.
5. Seeds qBittorrent configuration and optional credentials, writes `docker-compose.yml`, pulls images, and bootstraps Gluetun with repeated health polling before launching the full stack and helper aliases.

### 7) Runtime model
- Docker Compose profiles: `bootstrap` starts only Gluetun; `prod` adds qBittorrent, the Proton PF synchroniser (OpenVPN only), and the *arr services.
- Health gating: Gluetun must expose a healthy public IP (and OpenVPN PF when applicable) before `prod` services launch; qBittorrent’s health check polls `/api/v2/app/version` and each *arr container responds on its HTTP port.
- The `pf-sync` sidecar watches Gluetun’s `/v1/openvpn/portforwarded` endpoint, pushes the value into qBittorrent via `/api/v2/app/setPreferences`, and forces UPnP off so the Proton assignment always wins.
- Proton issues a fresh forwarded port every OpenVPN session. Expect qBittorrent’s listening port to change after reconnects or restarts.

### 8) Daily operations
- The installer copies `.aliasarr` to `${ARR_STACK_DIR}/.aliasarr` and appends `source ${ARR_STACK_DIR}/.aliasarr` to `~/.zshrc`. Source the file from other shells (e.g., `source ${ARR_STACK_DIR}/.aliasarr`) to load the helpers.
- Common helpers:

| Helper | Description |
| ------ | ----------- |
| `pvpn status` | Show Gluetun status, public IP, and the current forwarded port. |
| `pvpn connect` / `pvpn reconnect` | Start or restart Gluetun + qBittorrent. |
| `pvpn mode openvpn` / `pvpn mode wireguard` | Switch VPN mode (OpenVPN keeps Proton PF support). |
| `pvpn port` | Print the forwarded port only. |
| `qbtportsync` | Manually push the forwarded port into qBittorrent via its API (useful if PF drifts; replaces the legacy `pvpn portsync`). |
| `arrvpncountry` (`arr_vpn_country`) | Request a Proton exit country using the Gluetun control API, falling back to priority order. |
| `arrvpnfastest [limit]` (`arr_vpn_fastest`) | Probe preferred countries and switch to the fastest responsive endpoint. |

### 9) Security notes
- `arrconf/` and Proton credential files are forced to `700/600` to guard secrets; the installer rewrites `PROTON_USER` with `+pmp` inside `.env` when needed.
- Gluetun’s control API exposes `/v1/publicip/ip`, `/v1/openvpn/status`, `/v1/openvpn/portforwarded`, and related endpoints. Basic auth is enforced via `${ARR_DOCKER_DIR}/gluetun/auth/config.toml`, with the secret stored in `${ARR_STACK_DIR}/.env` as `GLUETUN_API_KEY`.
- The control server listens on `${HTTP_CONTROL_SERVER_ADDRESS}` inside the container and publishes `${GLUETUN_CONTROL_HOST_BIND}:${GLUETUN_CONTROL_PORT}` by default (loopback). Override these only when you can front the API with additional safeguards.

### 10) Logging
- Default: logs stream to the terminal only; temporary files are discarded at exit.
- `--debug` or `DEBUG=1` keeps a timestamped log in `${ARR_STACK_DIR}/arrstack-YYYYmmdd-HHMMSS.log` with permissions `0600` and refreshes the `arrstack-install.log` symlink.
- Optional `LOG_FILE_DEST` (within `${ARR_STACK_DIR}`) lets you pin the final log name; the installer enforces path safety before writing.

### 11) Troubleshooting
```bash
git mv arrconf/userconf.sh arrconf/userconf.defaults.sh
git commit -m "Track defaults; make userconf.sh user-local"
cp arrconf/userconf.defaults.sh arrconf/userconf.sh
printf "arrconf/userconf.sh\n" >> .gitignore
git add .gitignore arrconf/userconf.defaults.sh
git commit -m "Ignore userconf.sh; load defaults then overrides"
```

## Command-line flags & automation

You can steer the installer from the command line when you need to override defaults or run unattended:

- `--openvpn` — force the next run to pin `VPN_TYPE=openvpn` before writing `.env` or Compose files.
- `--wireguard` — switch to the WireGuard profile (no Proton port forwarding) for this run.
- `-y`, `--yes` — run non-interactively and auto-confirm the safety prompt (sets both `ASSUME_YES=1` and `ARR_NONINTERACTIVE=1` for this run). Exporting `ASSUME_YES=1` alone only skips the final confirmation; pair it with `--no-prompt` if you also want the other prompts suppressed.
- `--no-prompt`, `--non-interactive` — disable interactive prompts (defaults to reusing any existing Gluetun API key). Pair with `--rotate-apikey` when automation needs a fresh key.
- `--rotate-apikey`, `--rotate-api-key`, `--rotate-key` — regenerate `GLUETUN_API_KEY` on the next run, even if a key already exists.
- `-h`, `--help` — print available flags, subcommands, and examples, then exit.

The preflight always prefers the password stored in `gluetun/auth/config.toml` when `.env` and the TOML disagree, prints a warning, and syncs both files to that value. Interactive runs then show a masked preview and let you reuse or rotate; non-interactive runs keep the existing key unless you explicitly pass a rotate flag.

Subcommands still work as before — for example `./arrstack.sh conf-diff` compares `userconf.sh` to the latest defaults and exits.

# Query public IP via Gluetun control API
```bash
auth="--user gluetun:${GLUETUN_API_KEY}"  # omit if API key empty (WireGuard without RBAC is not allowed)
curl -fsS ${auth} http://${LOCALHOST_ADDR:-127.0.0.1}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip
```

# Proton OpenVPN only
```bash
curl -fsS ${auth} http://${LOCALHOST_ADDR:-127.0.0.1}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status
curl -fsS ${auth} http://${LOCALHOST_ADDR:-127.0.0.1}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded
```

# Confirm qBittorrent is using the forwarded port
```bash
curl -fsS http://${LOCALHOST_ADDR:-127.0.0.1}:${QBT_HTTP_PORT_HOST}/api/v2/app/preferences | jq '.listen_port'
```

| Issue | Resolution |
| ----- | ---------- |
| Preflight aborts: Proton creds missing | Fill `PROTON_USER`/`PROTON_PASS` in `${PROTON_AUTH_FILE}` (no `+pmp`) and rerun. |
| WireGuard mode fails to start | Ensure `proton.conf` (or a `wg*.conf`) exists in a searched directory and is a valid Proton export. |
| Ports already in use | Free the ports listed in the prerequisites; installer will try to kill conflicting listeners but may require manual cleanup. |
| LAN_IP reset to `0.0.0.0` | Update `LAN_IP` in `arrconf/userconf.sh` to a host-local RFC1918 address and rerun. |
| Need a new Gluetun API key | Run `./arrstack.sh --rotate-apikey --debug` (optional) to regenerate and persist a fresh key. |
| Proton PF mismatch (OpenVPN) | Compare the Gluetun and qBittorrent port values above; run `qbtportsync` or restart `pf-sync`. |

### 12) Limits & upgrades
- Proton port forwarding only works in OpenVPN mode; WireGuard runs without PF or the `pf-sync` helper.
- Expect Proton to rotate forwarded ports each reconnection; allow `pf-sync` (or `qbtportsync`) to keep qBittorrent aligned.
- FlareSolverr can spike CPU/RAM while solving challenges—budget headroom or scale the container accordingly.
- DNS-over-TLS (`DOT`) ships disabled for stability; set `DOT="on"` in `arrconf/userconf.sh` once you validate Proton’s DoT endpoints.
- Gluetun is pinned to `qmcgaw/gluetun:v3.38.0`; review upstream release notes before moving to a newer tag.

### 13) Uninstall / clean up
- Stop the stack but keep data: `cd ${ARR_STACK_DIR} && docker compose down --remove-orphans` (Compose file and `.env` live here).
- Full removal with backups: run `./arrstack-uninstall.sh` to archive configs, remove containers/images, purge native packages, and free mapped ports (review the script before executing).
- Configs persist under `${ARR_DOCKER_DIR}` and `${ARR_STACK_DIR}`; delete them manually if you no longer need cached data.
