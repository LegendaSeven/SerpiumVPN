# SerpiumVPN v1.0.18 — Relay Recovery + Orphan Guard

- Restores TryRecoverStoredProcess used by SettingsWindow.
- Recovers a live Serpium-owned Xray from gateway-process.json.
- Cleans an orphaned embedded xray.exe by exact executable path when the PID file is missing.
- Keeps unrelated Xray processes untouched.
- Prevents false port conflicts after restart, debug stop, clean, or rebuild.
