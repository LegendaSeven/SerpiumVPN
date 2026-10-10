# SerpiumVPN

Windows VPN client with saved connection profiles, per-application routing and website rules.

Enter a supported key or HTTPS subscription, select the applications, then connect.
The client validates the profile and probes the connection before reporting success.
Stop cancels an in-progress connection. Application switches update the live policy
and close the previous route's connections so the application reconnects on its new route.

The supported transports are Xray and sing-box TUN. SFP live routing uses the local
sing-box control API; no separate Serpium kernel driver is installed or required.
Secure profiles use Windows DPAPI. Temporary configurations are passed over stdin.
External component updates are checked for compatibility before replacement, with rollback.

Manual EXE selection and website rules are available in the Applications / Websites tabs.
See [manual applications and websites](docs/MANUAL_APPS_AND_WEBSITES.md) for priority and limitations.

## Build

Requires Windows, .NET 10 SDK; Inno Setup 6 for the installer.

```powershell
dotnet build SerpiumVPN.slnx -c Release
.\release.ps1 -Version 1.0.56.13 -SelfContained
```

Release outputs are under `publish/releases`. The release script checks the payload,
builds the ZIP and installer, and writes `update.json` with its ZIP SHA-256.
To publish checked artifacts, use `-PublishOnly -PublishGitHub -TargetCommit <commit>`
and optionally `-NotesFile <file>`. The commit must already exist on GitHub.

The window, executable, tray and installer shortcuts share `Assets/Serpium.App.ico`.
The in-app logo uses `Assets/Serpium.png`. The taskbar identity is `SerpiumVPN.Desktop`.
