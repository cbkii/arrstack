# arrstack

**arrstack** bundles ProtonVPN, Gluetun, qBittorrent and the *arr suite into a tidy, beginner‑friendly stack.
It runs every service behind ProtonVPN with automatic port forwarding, applies strict health gates, and ships helper aliases for daily use.

---

## Table of contents

1. [What this stack does / What it doesn't](#what-this-stack-does--what-it-doesnt)
2. [Features](#features)
3. [Security model & control server](#security-model--control-server)
4. [Prerequisites](#prerequisites)
5. [Quick start](#quick-start)
6. [Key environment variables (single source of truth)](#key-environment-variables-single-source-of-truth)
7. [Ports & paths](#ports--paths)
8. [Startup order & health-gates](#startup-order--health-gates)
9. [Default folders & mapping](#default-folders--mapping)
10. [Daily use](#daily-use)
11. [qBittorrent API usage & Proton PF behaviour](#qbittorrent-api-usage--proton-pf-behaviour)
12. [ProtonVPN + Gluetun notes (2024/2025)](#protonvpn--gluetun-notes-20242025)
13. [Optional: WireGuard fallback](#optional-wireguard-fallback)
14. [Troubleshooting](#troubleshooting)
15. [Privacy defaults (DoT) & upgrades](#privacy-defaults-dot--upgrades)
16. [Known limitations](#known-limitations)
17. [Uninstall / restore](#uninstall--restore)
18. [Notes](#notes)

---

## What this stack does / What it doesn't

### What this stack does
- Runs qBittorrent, Sonarr, Radarr, Prowlarr, Bazarr and FlareSolverr **behind ProtonVPN via Gluetun**.
- Uses **OpenVPN** by default because **Proton port forwarding (PF)** requires OpenVPN with the username suffix **`+pmp`**. The installer enforces this suffix automatically.
- Treats **PF availability** as a hard readiness gate: dependants only start once Gluetun is healthy **and** a PF port is issued.

### What this stack does not do
- **WireGuard PF**: Proton does **not** support PF on WireGuard in Gluetun; WG is an optional non-PF fallback only.
- Expose Gluetun’s control server to the internet. If you change `LAN_IP` to `0.0.0.0`, you **must** front it with TLS and strong authentication.

[Learn more about Proton PF requirements.](https://protonvpn.com/support/port-forwarding/)

---

## Features

- **Gluetun** (ProtonVPN) pinned to v3.38.0 with sensible defaults (DoT off for compatibility, stable health target, PF on, server list updates disabled).
- **qBittorrent** in Gluetun’s network namespace with automatic PF port sync.
- **Sonarr, Radarr, Prowlarr, Bazarr, FlareSolverr** routed through Gluetun.
- Service health checks with startup dependencies gated on Gluetun readiness.
- A comprehensive **`.aliasarr`** helper with `pvpn` and stack aliases.

---

## Security model & control server

Gluetun exposes an HTTP control server for status, PF and metadata on **`${GLUETUN_CONTROL_PORT:-8000}`**. The stack:

- Binds the control server to the LAN (`LAN_IP`) and enables RBAC/auth.
- Limits routes to the minimal surface this stack needs:
  - `GET /v1/publicip/ip` → public IP
  - `GET /v1/openvpn/status` → `{"status":"running"}`
  - `GET /v1/openvpn/portforwarded` → `IP:port` string (PF assignment)
- Stores the password in `.env` (`GLUETUN_API_KEY`) and injects Basic auth where required.
- Warns strongly against exposing the control server publicly without TLS and hardened auth. Gluetun tightened control-server auth around v3.39–v3.40; stay on ≥v3.39.1 if you change the pin.

**Never** publish the control server on the internet without a reverse proxy that enforces TLS and authentication.

See the [Gluetun control server documentation](https://github.com/qdm12/gluetun-wiki/blob/main/http_control_server.md) for the full API surface.

---

## Prerequisites

- Debian/Ubuntu-like system.
  - Docker & Compose v2, plus basic tools.
- ProtonVPN Plus or Unlimited plan with **port forwarding**.
  - Have your Proton OpenVPN/IKEv2 username and password ready (no `+pmp`; the installer adds it for OpenVPN automatically).

Install Docker & tooling (if needed):

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin curl wget openssl iproute2 xxd
sudo systemctl enable --now docker
```

> Pre-seeding qBittorrent credentials requires **OpenSSL 3** (with `kdf`), `xxd`, and `base64`. If any are missing, the installer falls back to qBittorrent's temporary password. Setting `QBT_USER`/`QBT_PASS` is optional.

---

## Quick start

1. **Clone the repository to its own folder:**

   ```bash
   mkdir -p ~/srv && cd ~/srv
   git clone https://github.com/cbkii/arrstack.git arrstackrepo
   cd arrstackrepo
   chmod +x arrstack.sh
   ```

   The installer writes configuration and runtime files under `~/srv/arrstack`, keeping the Git checkout clean.
   Sensitive VPN materials go in `./arrconf/` (created in this repo). Keep the directory `chmod 700` and any files inside `chmod 600`.

2. **Review and customise configuration:**

   * Defaults live in `arrconf/userconf.defaults.sh`. Copy it to `arrconf/userconf.sh` and edit the values you want to override; the overrides file is sourced on every run so you can adjust it before the first install or later and rerun the script.
  * Common tweaks: `LAN_IP`, download/media paths, qBittorrent credentials (`QBT_USER`/`QBT_PASS`), `QBT_WEBUI_PORT` (single source for the WebUI port), `GLUETUN_CONTROL_HOST`, `TIMEZONE`, and Proton server options (`SERVER_COUNTRIES`, `DEFAULT_VPN_TYPE`). Legacy `VPN_MODE` entries are migrated to `VPN_TYPE` automatically when you rerun the installer.
     * Set `QBT_PASS` in **plain text** – the installer hashes it with PBKDF2 (via OpenSSL 3, `xxd`, and `base64`) before writing `qBittorrent.conf`. If the hashing deps are missing, the script warns and ignores these values.

   ```bash
   cp arrconf/userconf.defaults.sh arrconf/userconf.sh  # first-time: create overrides
   nano arrconf/userconf.sh                             # edit overrides
   nano arrstack-uninstall.sh                           # optional reset script
   ```

   * Place Proton credentials in `./arrconf/proton.auth` (two lines: `PROTON_USER=...` and `PROTON_PASS=...`). Keep the folder `chmod 700` and the file `chmod 600`.
   * Proton port forwarding requires the OpenVPN username to end with **`+pmp`** (the installer auto-appends).
   * Provider mode means no `.ovpn` file is needed – `VPN_SERVICE_PROVIDER=protonvpn` handles Proton configs. Drop `.ovpn` files only when using a custom provider.
   * For WireGuard fallback, drop Proton `wg*.conf` files into `./arrconf/` (legacy `~/srv/...` paths are migrated automatically).
   * LinuxServer/qB requires the mapped port and `WEBUI_PORT` to match; editing `QBT_WEBUI_PORT` updates the compose mapping, container setting, healthcheck and port-sync sidecar together.
   * The installer writes a `.env` in `~/srv/arrstack` if you want to run `docker compose` manually.

3. **Run it** as your normal user:

   ```bash
   ./arrstack.sh
   ```

   * It stops any existing Arr/qBittorrent services, creates folders, backups and config files, and **warns if `./arrconf/proton.auth` is missing**.
   * Store your **plain** Proton username (OpenVPN / IKEv2 Username and Password, no `+pmp` suffix); the script adds `+pmp` automatically for OpenVPN port forwarding.

4. Open the UIs (replace `<LAN_IP>` with your host's LAN IP; default `192.168.1.11`):

   * **qBittorrent:** `http://${LAN_IP}:${QBT_HTTP_PORT_HOST}`
     * If `${QBT_USER}` and `${QBT_PASS}` are set and hashing deps are present (OpenSSL 3 with `kdf`, `xxd`, `base64`), the script hashes the password and you can log in with those credentials.
     * Otherwise the installer prints a temporary admin password from the logs; log in as `admin/<printed>` and change it in qBittorrent.
   * **Sonarr:** `http://${LAN_IP}:${SONARR_PORT}`
   * **Radarr:** `http://${LAN_IP}:${RADARR_PORT}`
   * **Prowlarr:** `http://${LAN_IP}:${PROWLARR_PORT}`
   * **Bazarr:** `http://${LAN_IP}:${BAZARR_PORT}`
   * **Gluetun API:** `http://${LAN_IP}:${GLUETUN_CONTROL_PORT}` (Basic auth user `gluetun`, password from `.env` `GLUETUN_API_KEY`)

   > All UIs are exposed via the Gluetun service and bound to `LAN_IP`. Set `LAN_IP` at the top of `arrstack.sh` (e.g. `${GLUETUN_CONTROL_HOST}` for local-only or another LAN address to expose to your network). If you set `LAN_IP=0.0.0.0` to expose beyond your LAN, front the Gluetun control server with TLS and a strong auth proxy.
   >
   > Only `${GLUETUN_CONTROL_HOST}` (Gluetun's loopback) can access the API without a login (`WebUI\BypassLocalAuth=true`) so the pf-sync sidecar works; browsers on the LAN still require a password.
   >
   > The control API password lives in `.env` as `GLUETUN_API_KEY`; the installer generates it if blank.
   >
> Tip: After you log in, change the generated password. UPnP/NAT-PMP is disabled automatically.
>
> If the installer can't find `LAN_IP` on the host, it warns and binds everything to `0.0.0.0`. Pair that fallback with host firewall rules before exposing services beyond your LAN.

### Config files

- `arrconf/userconf.defaults.sh` — **tracked defaults** (updated by repo on pull).
- `arrconf/userconf.sh` — **your local overrides** (NOT tracked).

The launcher loads defaults first, then your overrides:

1. `arrconf/userconf.defaults.sh`
2. `arrconf/userconf.sh` (if present)

To see what changed after updates:

```bash
./arrstack.sh conf-diff
```

If you don’t have a `userconf.sh` yet, the tool will offer to create it from the defaults.

#### One-time migration (if your userconf.sh is tracked)

```bash
git mv arrconf/userconf.sh arrconf/userconf.defaults.sh
git commit -m "Track defaults; make userconf.sh user-local"
cp arrconf/userconf.defaults.sh arrconf/userconf.sh
printf "arrconf/userconf.sh\n" >> .gitignore
git add .gitignore arrconf/userconf.defaults.sh
git commit -m "Ignore userconf.sh; load defaults then overrides"
```

---

## Key environment variables (single source of truth)

| Variable                | What it controls                             | Typical value / notes                                   |
|-------------------------|----------------------------------------------|---------------------------------------------------------|
| `LAN_IP`                | Bind for all exported ports                  | e.g. `192.168.1.11` (LAN only). Installer falls back to `0.0.0.0` if the host lacks this IP.        |
| `GLUETUN_CONTROL_HOST`  | Control server host **inside** the namespace | `127.0.0.1`                                             |
| `GLUETUN_CONTROL_PORT`  | Control server port                          | `8000`                                                  |
| `GLUETUN_HEALTH_TARGET` | Health-check target for Gluetun              | `1.1.1.1:443` (adjust if your ISP blocks it)            |
| `GLUETUN_API_KEY`       | HTTP control server password                 | auto-generated; stored in `.env`                        |
| `QBT_WEBUI_PORT`        | qB **internal** WebUI port                   | `8080`                                                  |
| `QBT_HTTP_PORT_HOST`    | qB **host** port mapping                     | e.g. `8081` or another free port                        |
| `PROTON_USER` / `PROTON_PASS` | Proton OpenVPN credentials (plain user; script adds `+pmp`) | required for PF                                      |
| `SERVER_COUNTRIES`      | Allowed countries (OpenVPN)                  | start with `Netherlands` (known PF region)             |
| `SERVER_CC_PRIORITY`    | Optional priority list for CLI helpers       | set in `userconf.sh`; CLI falls back to a built-in list if unset |
| `DEFAULT_VPN_TYPE`      | Starting VPN mode (`openvpn` or `wireguard`) | `openvpn` for PF. Legacy `VPN_MODE` values are mapped automatically. |
| `UPDATER_PERIOD`        | Gluetun server list updater                  | `24h` (`0` disables updates)                            |
| `DOT`                   | DNS-over-TLS in Gluetun                      | `off` by default (compatibility)                        |
| `TIMEZONE`              | TZ applied to containers                     | e.g. `Australia/Sydney`                                 |
| `QBT_USER` / `QBT_PASS` | Optional preseeded qB credentials            | requires OpenSSL 3 + `xxd` + `base64`                   |
---

## Ports & paths

### Ports (host → container, via Gluetun namespace)

| Service              | Host mapping                              | Container endpoint                    |
|----------------------|-------------------------------------------|---------------------------------------|
| qBittorrent WebUI    | `${LAN_IP}:${QBT_HTTP_PORT_HOST}`          | `127.0.0.1:${QBT_WEBUI_PORT}`         |
| Gluetun control API  | `${LAN_IP}:${GLUETUN_CONTROL_PORT}`        | `127.0.0.1:${GLUETUN_CONTROL_PORT}`   |
| Sonarr               | `${LAN_IP}:${SONARR_PORT}`                 | `127.0.0.1:${SONARR_PORT}`            |
| Radarr               | `${LAN_IP}:${RADARR_PORT}`                 | `127.0.0.1:${RADARR_PORT}`            |
| Prowlarr             | `${LAN_IP}:${PROWLARR_PORT}`               | `127.0.0.1:${PROWLARR_PORT}`          |
| Bazarr               | `${LAN_IP}:${BAZARR_PORT}`                 | `127.0.0.1:${BAZARR_PORT}`            |
| FlareSolverr         | `${LAN_IP}:${FLARESOLVERR_PORT}`           | `127.0.0.1:${FLARESOLVERR_PORT}`      |
| Proton PF (BitTorrent)| n/a (assigned dynamically by Proton)       | forwarded directly inside qBittorrent |

### Paths (container)

- Downloads: `/downloads` (incomplete) → qB completes to `/completed`
- Media libraries (defaults): `/tv`, `/movies`, `/subs`
- Ensure Arr root folders match these container paths exactly.

---

## Startup order & health-gates

```mermaid
flowchart TD
  A[Gluetun container started] --> B[Arr apps (Sonarr/Radarr/\nProwlarr/Bazarr/FlareSolverr)]
  A --> C{Gluetun healthy \n+ PF assigned}
  C --> D[qBittorrent healthy]
  C --> E[pf-sync applying PF]
```

Services are split across two Compose profiles:

* **`bootstrap`** — Gluetun plus the Arr/indexer apps. They depend on `condition: service_started`, so they can initialise while Gluetun negotiates Proton PF.
* **`prod`** — Adds qBittorrent and, when `VPN_TYPE=openvpn`, the pf-sync sidecar. These still require Gluetun to report healthy **and** return a PF port.

The installer runs `bootstrap` first, waits up to ~600 s for Gluetun to report healthy with a port, then promotes the `prod` profile. If you manage the stack manually, mirror that flow:

```bash
docker compose --profile bootstrap up -d
# wait for Gluetun health + PF
docker compose --profile prod up -d
```

All services keep their individual healthchecks; only qBittorrent (and pf-sync when OpenVPN is in use) gate on Gluetun health.

Service healthchecks stay on loopback HTTP endpoints that do **not** require API keys. Arr applications have historically moved or restricted `/ping`-style endpoints, so simple local HTTP/TCP checks remain stable across upstream updates.

---

## Default folders & mapping

- Base: `~/srv`
- Compose & `.env`: `~/srv/arrstack`
  - `docker compose` explicitly uses this file via `--env-file` (`ARR_ENV_FILE`)
- App data: `~/srv/docker/<service>`
- Downloads: `~/Downloads` → mounted in qB as `/downloads`
- Completed: `~/Downloads/completed` → `/completed`
- Media libraries (defaults):
  - TV: `/media/arrs/shows` → `/tv`
  - Movies: `/media/arrs/movies` → `/movies`
  - Subs: `/media/arrs/subs` → `/subs`

In each Arr app, add the **qBittorrent** client and ensure paths match these container paths.

---

## Daily use

The installer drops helper aliases at `~/srv/arrstack/.aliasarr` and sources them from `~/.zshrc`:

```bash
# already added to ~/.zshrc
[ -f ~/srv/arrstack/.aliasarr ] && source ~/srv/arrstack/.aliasarr
pvpn status   # show mode, public IP, forwarded port
```

Common `pvpn` commands:

```bash
pvpn connect      # start Gluetun + qBittorrent
pvpn reconnect    # restart Gluetun
pvpn mode ovpn    # switch to OpenVPN (recommended for port forwarding)
pvpn mode wg      # switch to WireGuard (optional)
pvpn creds        # update Proton username/password (adds +pmp automatically)
pvpn paths        # show credential & config locations
pvpn portsync     # force qB to use the currently forwarded port
```

1. **Initial location is random within `SERVER_COUNTRIES`.** Keep the list short (1–3) and start with countries that reliably support Proton port forwarding. We default to:

   ```
   SERVER_COUNTRIES="Netherlands"
   ```

   * Why Netherlands? Proton exposes the broadest set of PF-capable OpenVPN servers there. Once you confirm port forwarding works, expand the list (e.g. Switzerland, Iceland, Sweden) or pin specific endpoints with `SERVER_HOSTNAMES`.

2. **Switching later** is easy via `.aliasarr`:

  * `arr_vpn_country "<Country>"` — switch to a specific country; if it fails, the function retries through `SERVER_CC_PRIORITY` (falls back to a built-in list if unset).
  * `arr_vpn_fastest [N]` — probe the first *N* countries in `SERVER_CC_PRIORITY` (default 6; built-in list used if unset), pick the lowest RTT from AU, and switch there.
   * `arr_vpn_servers` — list Proton countries from the current server list.

3. **Priority list used for switching/speed trials from Australia** (fast → slow):

   ```
   SERVER_CC_PRIORITY="Australia,Singapore,Japan,Hong Kong,United States,United Kingdom,Netherlands,Germany,Switzerland,Spain,Romania,Luxembourg"
   ```

   * Rationale: geographic proximity/typical subsea paths from AU → SE/E Asia → US-West → Western Europe. Validate with your line by running `arr_vpn_fastest`.

---

## qBittorrent API usage & Proton PF behaviour

### qBittorrent endpoints we rely on

- **Healthcheck:** `GET http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/version` → 200 OK.
- **Apply Proton PF port:** `POST http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/setPreferences` with JSON body `{"listen_port":<integer>,"upnp":false}`.
  - `listen_port` **must** be an integer (unquoted). qB rejects quoted numbers.
  - UPnP/NAT-PMP remain disabled to prevent clobbering the Proton-assigned port.

See the [qBittorrent Web API documentation](https://github.com/qbittorrent/qBittorrent/wiki/Web-API-Documentation#application) for reference.

### Proton port forwarding behaviour

- Proton PF is only available on **OpenVPN** and requires the username suffix `+pmp`. The installer ensures the suffix is present when writing `.env`.
- The stack treats PF as a readiness gate. Gluetun must return an `IP:port` string from `/v1/openvpn/portforwarded` before qBittorrent starts.
- A sidecar polls the control API every 45 seconds and applies the current PF port through qBittorrent’s API.
- The forwarded port is session-based; expect it to change whenever Gluetun reconnects.

---

## ProtonVPN + Gluetun notes (2024/2025)

- Use Proton’s OpenVPN credentials with the `+pmp` suffix for port forwarding. These differ from your standard Proton login.
- The stack pins Gluetun to `v3.38.0`. Gluetun `v3.39+` filters Proton servers too aggressively and often reports “no servers available”. We leave `UPDATER_PERIOD=24h` so Gluetun refreshes Proton’s server metadata once a day; set it to `0` if you need to freeze a known-good list. If issues persist, specify exact `SERVER_HOSTNAMES` like `node-xx-xx.protonvpn.net`.
- Port forwarding only works on Proton’s P2P servers and a new port is assigned each session. qBittorrent’s listening port is synced automatically by a sidecar that polls Gluetun’s API.
- Recommended health check tuning: `HEALTH_VPN_DURATION_INITIAL=30s` and `HEALTH_SUCCESS_WAIT_DURATION=10s` with `HEALTH_TARGET_ADDRESS=1.1.1.1:443`.

---

## Optional: WireGuard fallback

If you want to enable the fallback to wireguard, download a Proton **WireGuard** `.conf` from their site and place it in `./arrconf/` (name it `wg*.conf` or `proton.conf`).

1. Re-run the installer once (it may auto-seed the private key).
2. Switch when you want:

   ```bash
   pvpn mode wg
   pvpn status
   ```

> Port forwarding is typically most reliable with **OpenVPN**. Use WG when PF is not required.

---

## Troubleshooting

### Quick checks

1. Confirm the container is up:

   ```bash
   docker ps | grep gluetun
   ```

2. Inspect Gluetun & PF status:

   ```bash
   curl -fsS http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/publicip/ip
   curl -fsS http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/openvpn/status
   curl -fsS http://${LAN_IP}:${GLUETUN_CONTROL_PORT}/v1/openvpn/portforwarded
   ```

3. Verify the effective Proton username ends with `+pmp`:

   ```bash
   grep OPENVPN_USER ~/srv/arrstack/.env
   ```

4. Query qBittorrent directly:

   ```bash
   curl -fsS http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/version
   curl -fsS -X POST --data 'json={"cmd":"preferences"}' http://127.0.0.1:${QBT_WEBUI_PORT}/api/v2/app/preferences
   ```

5. Force a PF refresh:

   ```bash
   pvpn portsync
   ```

### Common scenarios

- **Slow first boot?** Images must pull and Gluetun has a generous health `start_period`. Expect the first run to take longer; subsequent restarts reuse cached images.
- **Gluetun unhealthy?** Check `docker logs -f gluetun` and verify DNS/TLS reachability. Consider lowering `HEALTH_TARGET_ADDRESS` to a local resolver if you block 1.1.1.1.
- **DNS issues?** With `DOT=off` the stack uses plain DNS for compatibility. Enable `DOT=on` once your resolver supports it (see [privacy defaults](#privacy-defaults-dot--upgrades)).
- **WireGuard MTU problems?** Lower `WIREGUARD_MTU` in `.env` from `1320` to `1280` or `1200`.
- **Need to reseed Proton creds?** Update `./arrconf/proton.auth` and rerun the installer.

To adjust exposure, edit `LAN_IP` in `arrstack.sh` (e.g., `${GLUETUN_CONTROL_HOST}` for local-only or `0.0.0.0` for all) and rerun:

```bash
~/srv/arrstackrepo/arrstack.sh
```

---

## Privacy defaults (DoT) & upgrades

### DNS-over-TLS (DoT)

- Default: `DOT=off` for compatibility during first run or on flaky resolvers.
- After the stack is stable, consider setting `DOT=on` to encrypt DNS inside Gluetun.

### Upgrading Gluetun and the stack

- Re-run `./arrstack.sh` or `docker compose pull && docker compose up -d` in `~/srv/arrstack` to refresh images.
- Review Gluetun release notes before unpinning. We suggest targeting ≥`v3.39.1` (or current stable) for improved control-server auth if Proton’s server filtering issues are resolved.
- If a new Gluetun release breaks Proton discovery, pin back to `v3.38.0` or a known-good tag and optionally set `SERVER_HOSTNAMES`.

---

## Known limitations

- Proton PF is OpenVPN-only (`+pmp` suffix required); WireGuard fallback has **no** PF support.
- FlareSolverr can briefly spike CPU/RAM while solving challenges; short bursts are expected.
- Proton only forwards one port per session; reconnects change the port and trigger qBittorrent updates.

---

## Uninstall / restore

Run the provided `arrstack-uninstall.sh` script to back up existing configurations to `~/srv/backups/uninstall-<timestamp>/` and remove Docker containers, native packages and related files. After cleanup you can re-run `arrstack.sh` to reinstall. Restores can be made by extracting the archives from the backup directory back to their original locations.

```bash
~/srv/arrstack-uninstall.sh
```

---

## Notes

- Proton credentials live at `./arrconf/proton.auth` (`chmod 600` inside a `chmod 700` folder). Legacy files under `~/srv/docker/gluetun/` or `~/srv/wg-configs/` are migrated automatically. Use your plain Proton username; `+pmp` is added automatically for OpenVPN port forwarding.
- `.env` is also `chmod 600` and only contains what Compose needs.
- You can customise paths and ports by editing the variables at the top of the script before running it.
- Scripts avoid `set -e` and log warnings by default; using `die` only for genuine unsafe conditions.
