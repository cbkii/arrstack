# arrconf

This directory stores ProtonVPN credentials, optional WireGuard profiles and configuration overrides.

- `proton.auth` – two lines `PROTON_USER=...` and `PROTON_PASS=...` (no `+pmp`).
- `wg*.conf` – Proton WireGuard configuration files.
- `userconf.defaults.sh` – tracked defaults sourced by `arrstack.sh`.
- `userconf.sh` – your local overrides (copy from defaults and edit).

Keep this folder at `700` and files at `600` to protect secrets.
