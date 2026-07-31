# SerpiumVPN 1.0.17-dev — Xray Gateway Core

- Generates a local VLESS/TCP Xray server configuration.
- Starts and stops `bin_files/relay/xray.exe`.
- Waits for the gateway TCP port to become available.
- Shows lifecycle state and live stdout/stderr logs in Settings.
- Generates a matching `serpium://relay/` key.
- Tailscale transport and client connection are not enabled yet.
