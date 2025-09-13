# arr-stack
ProtonVPN (OpenVPN-first, WG fallback) + Gluetun + qBittorrent PF + *arr + FlareSolverr

A tidy, beginner-friendly way to run qBittorrent, Sonarr, Radarr, Prowlarr, Bazarr and FlareSolverr **behind ProtonVPN** using **Gluetun**.  
Defaults: **OpenVPN** for reliable port forwarding, **WireGuard** available as an optional fallback.

---

## What you get

- **Gluetun** (ProtonVPN) with sensible defaults (DoT off, stable health target, PF on).
- **qBittorrent** in Gluetun’s network namespace.
- **Auto Port-Forward monitor** that keeps qBittorrent’s listen port in sync.
- **Sonarr, Radarr, Prowlarr, Bazarr, FlareSolverr**.
- A comprehensive **`.aliasarr`** helper with `pvpn` and stack aliases.

---

## Prerequisites

- Debian/Ubuntu-like system.
- Docker & Compose v2, plus basic tools.

Install (if needed):
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin curl jq openssl iproute2
sudo systemctl enable --now docker
````

---

## Quick start

1. **Save the installer script** (the merged `arr-stack` installer) somewhere, e.g.:

   ```bash
   mkdir -p ~/srv && cd ~/srv
   nano arrstack.sh    # paste the script
   chmod +x arrstack.sh
   ```

2. **Run it** as your normal user:

   ```bash
   ~/srv/arrstack.sh
   ```

   * It will create folder structure, backups, config files and **prompt for ProtonVPN credentials** if they’re not already set.
   * Store your **plain** Proton username (no `+pmp`); the script handles `+pmp` automatically for OpenVPN PF.

3. Open the UIs:

   * **qBittorrent:** `http://<your-host>:8080` (default login `admin` / `adminadmin`)
   * **Sonarr:** `http://<your-host>:8989`
   * **Radarr:** `http://<your-host>:7878`
   * **Prowlarr:** `http://<your-host>:9696`
   * **Bazarr:** `http://<your-host>:6767`

> Tip: After you log in, change all default passwords in each app.

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

In each Arr app, add the **qBittorrent** client and make sure paths match these containers paths.

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

The installer is safe to re-run; it will pull new images and start cleanly:

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

| Service         | Port | Notes                                 |
| --------------- | ---- | ------------------------------------- |
| qBittorrent UI  | 8080 | via Gluetun’s network namespace       |
| Gluetun Control | 8000 | bound to `127.0.0.1` (localhost only) |
| BitTorrent (PF) | dynamic | Proton-assigned; no host binding |
| Sonarr          | 8989 |                                       |
| Radarr          | 7878 |                                       |
| Prowlarr        | 9696 |                                       |
| Bazarr          | 6767 |                                       |
| FlareSolverr    | 8191 |                                       |

---

## Troubleshooting (short)

* **Check status & PF:** `pvpn status`
* **Logs:** `docker logs -f gluetun`
* **Public IP:** `curl -fsS http://127.0.0.1:8000/v1/publicip/ip`
* **Forwarded port (OpenVPN):** `curl -fsS http://127.0.0.1:8000/v1/openvpn/portforwarded`
* **Force qB to current PF:** `pvpn portsync`

If you change default folders/ports in the script, update the mounts/ports in `~/srv/arr-stack/docker-compose.yml` accordingly and run:

```bash
cd ~/srv/arr-stack
docker compose up -d
```

---

## Uninstall / restore

Stop the stack:

```bash
cd ~/srv/arr-stack
docker compose down
```

Backups live under `~/srv/backups/backup-YYYYmmdd-HHMMSS/`.
You can restore any app’s tarball to its previous location if you want to go back to native installs later.

---

## Notes

* Proton credentials are stored at `~/srv/docker/gluetun/proton-credentials.conf` (`chmod 600`).
* `.env` is also `chmod 600` and only contains what Compose needs.
* You can customise paths and ports by editing the variables at the top of the script before running it.
