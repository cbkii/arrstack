# arr-stack
ProtonVPN (OpenVPN-first, WG fallback) + Gluetun + qBittorrent PF + *arr + FlareSolverr

A tidy, beginner-friendly way to run qBittorrent, Sonarr, Radarr, Prowlarr, Bazarr and FlareSolverr **behind ProtonVPN** using **Gluetun**.  
Defaults: **OpenVPN** for reliable port forwarding, **WireGuard** available as an optional fallback.

---

## What you get

- **Gluetun** (ProtonVPN) with sensible defaults (DoT off, stable health target, PF on).
- **qBittorrent** in Gluetun’s network namespace.
- **Automatic qBittorrent port sync** via Gluetun’s NAT-PMP hook (no background monitor).
- **Sonarr, Radarr, Prowlarr, Bazarr, FlareSolverr**.
- A comprehensive **`.aliasarr`** helper with `pvpn` and stack aliases.

---

## Prerequisites

- Debian/Ubuntu-like system.
  - Docker & Compose v2, plus basic tools.

  Install (if needed):
  ```bash
  sudo apt update
  sudo apt install -y docker.io docker-compose-plugin curl openssl iproute2
  sudo systemctl enable --now docker
  ```

---

## Quick start

1. **Save the installer** (and optional uninstaller) somewhere, e.g.:

   ```bash
   mkdir -p ~/srv && cd ~/srv
   nano arrstack.sh             # paste the installer
   nano arrstack-uninstall.sh   # optional reset script
   chmod +x arrstack.sh arrstack-uninstall.sh
   ```

2. **Run the installer** as your normal user:

   ```bash
   ~/srv/arrstack.sh
   ```

   * It will create folder structure, backups, config files and **prompt for ProtonVPN credentials** if they’re not already set.
   * Store your **plain** Proton username (OpenVPN / IKEv2 Username and Password, no `+pmp` suffix); the script handles `+pmp` automatically for OpenVPN PF.
   * To **reset a previous install** (backing up configs to `~/srv/backups/uninstall-<timestamp>/`), run `arrstack-uninstall.sh` first and then re-run the installer.

  3. Open the UIs (replace `<LAN_IP>` with your host's LAN IP; default `192.168.1.50`):

     * **qBittorrent:** `http://<LAN_IP>:8080` – installer prints an initial password; set `${QBT_USER}/${QBT_PASS}` before installation to preseed.
     * **Sonarr:** `http://<LAN_IP>:8989`
     * **Radarr:** `http://<LAN_IP>:7878`
     * **Prowlarr:** `http://<LAN_IP>:9696`
     * **Bazarr:** `http://<LAN_IP>:6767`
     * **Gluetun API:** `http://<LAN_IP>:8000` (Basic auth user `gluetun`, password from `.env` `GLUETUN_API_KEY`)

     > All UIs are exposed via the Gluetun service and bound to `LAN_IP`. Set `LAN_IP` at the top of `arrstack.sh` (e.g. `127.0.0.1` for localhost-only or another LAN address to expose to your network).

     > The control API password lives in `.env` as `GLUETUN_API_KEY`; the installer generates it if blank.

     > Tip: After you log in, change the generated password. UPnP/NAT-PMP is disabled automatically.

---

## Default folders & mapping

* Base: `~/srv`
* Compose & `.env`: `~/srv/arr-stack`
* App data: `~/srv/docker/<service>`
* Downloads: `~/downloads` → mounted in qB as `/downloads`
* Completed: `~/downloads/completed` → `/completed`
* Media libraries (examples):

  * TV: `/media/mediasmb/library/tv` → `/tv`
  * Movies: `/media/mediasmb/library/movies` → `/movies`

  In each Arr app, add the **qBittorrent** client and make sure paths match these container paths.

---

## Daily use

The installer drops helper aliases at `~/srv/arr-stack/.aliasarr` and sources them from `~/.zshrc`:

```bash
# already added to ~/.zshrc
[ -f ~/srv/arr-stack/.aliasarr ] && source ~/srv/arr-stack/.aliasarr
pvpn status   # show mode, public IP, forwarded port
```

Common `pvpn` commands:

```bash
pvpn connect      # start Gluetun + qBittorrent
pvpn reconnect    # restart Gluetun
pvpn mode ovpn    # switch to OpenVPN (recommended for port forwarding)
pvpn mode wg      # switch to WireGuard (optional)
pvpn creds        # update Proton username/password (adds +pmp automatically)
pvpn portsync     # force qB to use the currently forwarded port
```

---

## Optional: WireGuard fallback

If you have a Proton **WireGuard** `.conf`:

1. Drop it in `~/srv/docker/gluetun/` or `~/srv/pvpn-backup/`.
2. Re-run the installer once (it may auto-seed the private key).
3. Switch when you want:

   ```bash
   pvpn mode wg
   pvpn status
   ```

> Port forwarding is typically most reliable with **OpenVPN**. Use WG when PF is not required.

---

## Update the stack

  The installer is safe to re-run; it will pull new images and start cleanly. Gluetun’s built-in updater is disabled (`UPDATER_PERIOD=`). Refresh server data by pulling a new image or temporarily setting `UPDATER_PERIOD=24h` in the `.env` file. For a **full reset**, run `arrstack-uninstall.sh` (backups to `~/srv/backups/`) and then reinstall.

```bash
~/srv/arrstack.sh
```

Or:

```bash
cd ~/srv/arr-stack
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
* **DNS issues:** DoT is disabled by default (`DOT=off` in `.env`).
* **Re-seed Proton creds:** copy fresh files to `${PROTON_CREDS_FBAK}` and re-run the installer.

To adjust exposure, edit `LAN_IP` in `arrstack.sh` (e.g., `127.0.0.1` for localhost or `0.0.0.0` for all) and rerun:

```bash
cd ~/srv/arr-stack
docker compose up -d
```

---

## Uninstall / restore

Run the provided `arrstack-uninstall.sh` script to back up existing configurations to `~/srv/backups/uninstall-<timestamp>/` and remove Docker containers, native packages and related files. After cleanup you can re-run `arrstack.sh` to reinstall. Restores can be made by extracting the archives from the backup directory back to their original locations.

```bash
~/srv/arrstack-uninstall.sh
```


---

## Notes

* Proton credentials are stored at `~/srv/docker/gluetun/proton-credentials.conf` (`chmod 600`). Use your plain Proton username; `+pmp` is added automatically for OpenVPN port forwarding.
* `.env` is also `chmod 600` and only contains what Compose needs.
* You can customise paths and ports by editing the variables at the top of the script before running it.
