# arrstack

**arrstack** bundles ProtonVPN, Gluetun, qBittorrent and the *arr suite into a tidy, beginner‑friendly stack.
It runs every service behind ProtonVPN with automatic port forwarding and provides helpful aliases for daily use.

By default the stack connects with **OpenVPN** for reliable port forwarding; **WireGuard** can be enabled as an optional fallback.

---

## Features

- **Gluetun** (ProtonVPN) with sensible defaults (DoT off for compatibility, stable health target, PF on, daily server list updates).
- **qBittorrent** in Gluetun’s network namespace.
- **Automatic qBittorrent port sync** via Gluetun’s NAT-PMP hook (no background monitor).
- **Sonarr, Radarr, Prowlarr, Bazarr, FlareSolverr**.
- A comprehensive **`.aliasarr`** helper with `pvpn` and stack aliases.

---

## Prerequisites

- Debian/Ubuntu-like system.
  - Docker & Compose v2, plus basic tools.
- ProtonVPN Plus or Unlimited plan with **port forwarding**.
  - Have your Proton OpenVPN/IKEv2 username and password ready.

  Install Docker & tools (if needed):
  ```bash
  sudo apt update
  sudo apt install -y docker.io docker-compose-plugin curl wget openssl iproute2
  sudo systemctl enable --now docker
  ```

> Pre-seeding qBittorrent credentials requires **OpenSSL 3** (Ubuntu 22.04+ ships it). If only an older OpenSSL is found, the installer falls back to qBittorrent's temporary password. Setting `QBT_USER`/`QBT_PASS` is optional.

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

   * Defaults live in the `USER CONFIG` section of `arrstack.sh`. To keep the installer clean, override any of these settings in `arrconf/userconf.sh` by uncommenting the lines you need; the file is sourced on every run so you can adjust it before the first install or later and rerun the script.
  * Common tweaks: `LAN_IP`, download/media paths, qBittorrent credentials (`QBT_USER`/`QBT_PASS`), `QBT_WEBUI_PORT` (single source for the WebUI port), `GLUETUN_CONTROL_HOST`, `TIMEZONE`, and Proton server options (`SERVER_COUNTRIES`, `DEFAULT_VPN_MODE`).
    * Set `QBT_PASS` in **plain text** – the installer hashes it with PBKDF2 (via OpenSSL 3) before writing `qBittorrent.conf`. If OpenSSL 3 isn't available, the script warns and ignores these values.

   ```bash
   nano arrconf/userconf.sh     # uncomment overrides
   nano arrstack.sh             # view all defaults
   nano arrstack-uninstall.sh   # optional reset script
   ```

    * Place Proton credentials in `./arrconf/proton.auth` (two lines: `PROTON_USER=...` and `PROTON_PASS=...`). Keep the folder `chmod 700` and the file `chmod 600`.
    * Proton port forwarding requires the OpenVPN username to end with **`+pmp`** (the installer auto-appends).
    * Provider mode means no `.ovpn` file is needed – `VPN_SERVICE_PROVIDER=protonvpn` handles Proton configs. Drop `.ovpn` files only when using a custom provider.
    * For WireGuard fallback, drop Proton `wg*.conf` files into `./arrconf/` (legacy `~/srv/...` paths are migrated automatically).
    * LinuxServer/qB requires the mapped port and `WEBUI_PORT` to match; editing `QBT_WEBUI_PORT` updates the compose mapping, container setting, healthcheck and port-forward hook together.

3. **Run it** as your normal user:

   ```bash
   ./arrstack.sh
   ```

     * It stops any existing Arr/qBittorrent services, creates folders, backups and config files, and **warns if `./arrconf/proton.auth` is missing**.
     * Store your **plain** Proton username (OpenVPN / IKEv2 Username and Password, no `+pmp` suffix); the script adds `+pmp` automatically for OpenVPN port forwarding.

4. Open the UIs (replace `<LAN_IP>` with your host's LAN IP; default `192.168.1.50`):

    * **qBittorrent:** `http://${LAN_IP}:${QBT_HTTP_PORT_HOST}`
      * If `${QBT_USER}` and `${QBT_PASS}` (plain text) are set and OpenSSL 3 is available, the script hashes the password and you can log in with those credentials.
      * Otherwise (or if OpenSSL 3 is missing) the installer prints a temporary admin password from the logs; log in as `admin/<printed>` and change it in qBittorrent.
     * **Sonarr:** `http://${LAN_IP}:${SONARR_PORT}`
     * **Radarr:** `http://${LAN_IP}:${RADARR_PORT}`
     * **Prowlarr:** `http://${LAN_IP}:${PROWLARR_PORT}`
     * **Bazarr:** `http://${LAN_IP}:${BAZARR_PORT}`
     * **Gluetun API:** `http://${LAN_IP}:${GLUETUN_CONTROL_PORT}` (Basic auth user `gluetun`, password from `.env` `GLUETUN_API_KEY`)

    > All UIs are exposed via the Gluetun service and bound to `LAN_IP`. Set `LAN_IP` at the top of `arrstack.sh` (e.g. `${GLUETUN_CONTROL_HOST}` for local-only or another LAN address to expose to your network). If you set `LAN_IP=0.0.0.0` to expose beyond your LAN, front the Gluetun control server with TLS and a strong auth proxy.

     > The WebUI is bound to `${LAN_IP}:${QBT_HTTP_PORT_HOST}`. Set `LAN_IP=${GLUETUN_CONTROL_HOST}` for host-only access or your host's LAN address to reach it from the network.

     > Only `${GLUETUN_CONTROL_HOST}` (Gluetun's loopback) can access the API without a login (`WebUI\BypassLocalAuth=true`) so the port-forward hook works; browsers on the LAN still require a password.

    > The control API password lives in `.env` as `GLUETUN_API_KEY`; the installer generates it if blank.

    > Tip: After you log in, change the generated password. UPnP/NAT-PMP is disabled automatically.

---

## Default folders & mapping

* Base: `~/srv`
* Compose & `.env`: `~/srv/arrstack`
* App data: `~/srv/docker/<service>`
* Downloads: `~/downloads` → mounted in qB as `/downloads`
* Completed: `~/downloads/completed` → `/completed`
* Media libraries (defaults):

  * TV: `/media/mediasmb/Shows` → `/tv`
  * Movies: `/media/mediasmb/Movies` → `/movies`
  * Subs: `/media/mediasmb/subs` → `/subs`

  In each Arr app, add the **qBittorrent** client and make sure paths match these container paths.

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

## Update the stack

The installer is safe to re-run; it will pull new images and start cleanly.
Gluetun’s server list updater runs daily (`UPDATER_PERIOD=24h`). Adjust or disable it in the `.env` file if desired.
For a **full reset**, run `arrstack-uninstall.sh` (backups to `~/srv/backups/`) and then reinstall.

```bash
~/srv/arrstackrepo/arrstack.sh
```

Or:

```bash
cd ~/srv/arrstack
docker compose pull
docker compose up -d
```

---

## Ports (host)

All services bind to `LAN_IP` (`192.168.1.50` by default).

| Service         | Port | Notes                                 |
| --------------- | ---- | ------------------------------------- |
| qBittorrent UI  | 8080 | bound to `LAN_IP` via Gluetun         |
| Gluetun Control | 8000 | bound to `LAN_IP`; auth `gluetun`/`GLUETUN_API_KEY` |
| BitTorrent (PF) | dynamic | Proton-assigned; no host binding |
| Sonarr          | 8989 | bound to `LAN_IP`                     |
| Radarr          | 7878 | bound to `LAN_IP`                     |
| Prowlarr        | 9696 | bound to `LAN_IP`                     |
| Bazarr          | 6767 | bound to `LAN_IP`                     |
| FlareSolverr    | 8191 | bound to `LAN_IP`                     |

---

## Troubleshooting (short)

* **Check status & PF:** `pvpn status`
* **Logs:** `docker logs -f gluetun`
* **Public IP:** `curl -u gluetun:<GLUETUN_API_KEY> http://${LAN_IP}:8000/v1/publicip/ip`
* **Forwarded port (OpenVPN):** `curl -u gluetun:<GLUETUN_API_KEY> http://${LAN_IP}:8000/v1/openvpn/portforwarded`
* **Force qB to current PF:** `pvpn portsync`
* **MTU issues (WireGuard):** lower `WIREGUARD_MTU` in `.env` from `1320` to `1280` or `1200`.
* **DNS issues:** Gluetun uses DNS over TLS by default; `DOT=off` trades privacy for compatibility.
* **Re-seed Proton creds:** update `./arrconf/proton.auth` and re-run the installer.

To adjust exposure, edit `LAN_IP` in `arrstack.sh` (e.g., `${GLUETUN_CONTROL_HOST}` for local-only or `0.0.0.0` for all) and rerun:

```bash
~/srv/arrstackrepo/arrstack.sh
```

---

## Uninstall / restore

Run the provided `arrstack-uninstall.sh` script to back up existing configurations to `~/srv/backups/uninstall-<timestamp>/` and remove Docker containers, native packages and related files. After cleanup you can re-run `arrstack.sh` to reinstall. Restores can be made by extracting the archives from the backup directory back to their original locations.

```bash
~/srv/arrstack-uninstall.sh
```

---

## Notes

* Proton credentials live at `./arrconf/proton.auth` (`chmod 600` inside a `chmod 700` folder). Legacy files under `~/srv/docker/gluetun/` or `~/srv/wg-configs/` are migrated automatically. Use your plain Proton username; `+pmp` is added automatically for OpenVPN port forwarding.
* `.env` is also `chmod 600` and only contains what Compose needs.
* You can customise paths and ports by editing the variables at the top of the script before running it.
