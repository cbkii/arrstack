# arrconf

This directory stores ProtonVPN credentials and optional WireGuard profiles.

- `proton.auth` – two lines `PROTON_USER=...` and `PROTON_PASS=...` (no `+pmp`).
- `wg*.conf` – Proton WireGuard configuration files.

Keep this folder at `700` and files at `600` to protect secrets.
