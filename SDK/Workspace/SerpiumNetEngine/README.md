# SerpiumNet External Engine 0.4.3 — Headscale Headless

This engine is loaded dynamically by SerpiumVPN and owns the packaged
`SerpiumNet.exe` process used by Relay gateway mode.

## Headless enrollment

Browser/Tailscale-cloud authorization is disabled.

Configuration is resolved in this order:

1. `SERPIUM_CONTROL_URL` environment variable;
2. `%APPDATA%\SerpiumVPN\SerpiumNet\headscale-control-url.txt`;
3. default `http://127.0.0.1:8080`.

A previously registered node reuses:

`%APPDATA%\SerpiumVPN\SerpiumNet\tailscaled.state`

For a fresh node, place a Headscale one-time preauth key on a single line in:

`%APPDATA%\SerpiumVPN\SerpiumNet\headscale-auth.key`

The file is deleted automatically only after `NODE_ONLINE` or `GATEWAY_READY`.
The key is never written to Serpium logs.

## Safety

- Public Tailscale control-plane fallback is rejected.
- A browser login URL is treated as an enrollment error, not opened.
- Stop kills the full SerpiumNet process tree and waits for confirmed exit.
- Persistent registration state is intentionally kept for quick later starts.
