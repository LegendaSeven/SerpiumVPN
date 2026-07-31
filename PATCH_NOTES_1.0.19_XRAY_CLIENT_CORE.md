# SerpiumVPN v1.0.19 — Xray Client Core

- Adds real client Connect / Disconnect controls.
- Parses a serpium:// relay key and generates configs/client.json.
- Starts a separate xray-client.exe process to avoid gateway conflicts.
- Opens a local SOCKS5 listener on 127.0.0.1:10808 by default.
- Uses separate client logs and client-process.json state.
- Keeps Gateway and Client lifecycle isolated.
- This patch establishes the local client proxy. Tailscale reachability and external-IP testing come next.
