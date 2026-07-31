# SerpiumVPN v1.0.18 — Xray Orphan Guard

- Cleans stale embedded xray.exe processes even if Clean/Rebuild deleted gateway-process.json.
- Matches the exact embedded executable path before stopping a process.
- Does not touch Xray instances launched from other folders.
- Waits for the port to be released before restarting the gateway.
- Preserves the existing PID/state guard as a second layer.
