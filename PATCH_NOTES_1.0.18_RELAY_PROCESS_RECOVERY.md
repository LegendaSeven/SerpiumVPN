# SerpiumVPN v1.0.18 — Relay Process Recovery

- Recovers a previously launched Serpium Xray process from gateway-process.json.
- Prevents false "port already in use" errors when the port belongs to Serpium's own gateway.
- Restores gateway UI state after application restart.
- Enables the Stop button for a recovered process.
- Keeps protection against unrelated processes occupying the same port.
