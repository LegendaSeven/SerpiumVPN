# SerpiumVPN v1.0.17 — Xray Shutdown & Release Guard

- Embedded Xray processes are stopped when SerpiumVPN exits.
- release.ps1 stops only xray.exe instances launched from bin_files\relay.
- Unrelated Xray installations are not touched.
- Prevents locked xray.exe files during build/publish.
