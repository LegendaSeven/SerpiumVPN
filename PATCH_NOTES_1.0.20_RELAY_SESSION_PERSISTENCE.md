# SerpiumVPN v1.0.20 — Relay Session Persistence

- SettingsWindow is now reused instead of recreated.
- Closing SettingsWindow hides it instead of stopping Gateway and Client.
- Reopening settings restores the same window, key, logs, ports, and live Relay session.
- Normal minimize behavior remains available.
- Full application exit stops Gateway and Client cleanly.
- App-level process cleanup remains as a final safety net.
