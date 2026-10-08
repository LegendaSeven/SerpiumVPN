# SerpiumVPN

SerpiumVPN is a Windows desktop application for VPN connections with per-application routing. The project is built as a WPF app on .NET and wraps several third-party networking components behind a simple desktop interface.

## Features

- Windows WPF interface for starting and stopping profiles.
- Connection key input and application switches for selective VPN routing.
- Two switchable themes: «Полуночная Змеюка» (midnight/mint) and «Нежная Булка» (soft pink).
- Telegram Desktop WS/MTProto local proxy mode.
- Updates for Telegram WS Proxy, sing-box and Xray Core.
- Third-party license and attribution files included in the repository.

## Appearance

The theme button in the header switches the main screen immediately, including
connection indicators, application switches and the native light/dark title bar.
It preserves the connection, entered key, application selection and list position.
The preference is saved per user in `%LocalAppData%\SerpiumVPN\appearance.txt`;
the default is «Полуночная Змеюка». Missing or unrecognized preferences use the default.

## Application discovery

Application switches apply live through the SFP user-mode routing controller.
The tunnel stays running: the controller confirms that sing-box loaded the new
policy, then closes only that application's connections still using the previous
route. Other applications remain connected. TCP connections must reconnect;
the application controls how quickly it retries. See `docs/SFP_LIVE_SWITCH.md`.

The application list excludes Windows components, registered service executables,
updaters and background helpers. Common network clients are available before launch;
other interactive applications are learned from internet TCP connections owned by
the current user. While the VPN is running, confirmed TUN destinations also provide
UDP evidence. A local listener or LAN connection alone does not qualify an app.
An unknown UDP-only app may therefore first appear after the VPN has been started.

Registrations are cached for five minutes; process/network observations refresh every
five seconds. Previously observed applications are remembered locally for up to 90
days without storing destination addresses. Removed executables are discarded.

## Requirements

- Windows
- .NET SDK 10.0 or newer for building from source
- Administrator privileges may be required for packet interception components

## Build

From the project directory:

```powershell
dotnet build SerpiumVPN.csproj
```

The project targets `net10.0-windows`.

## App Updates

SerpiumVPN uses an Inno Setup primary installer and a small bundled `SerpiumUpdater.exe` for application patches. The in-app "Проверить патч программы" button checks GitHub Releases at:

```text
https://github.com/LegendaSeven/SerpiumVPN
```

Local release build:

```powershell
.\release.ps1 -Version 1.0.1
```

Upload the generated `SerpiumVPN-1.0.1.zip` and `update.json` from `publish\releases` to a GitHub Release, or let GitHub Actions do it.

GitHub Actions release flow:

```powershell
git tag v1.0.1
git push origin v1.0.1
```

The `Release` workflow builds the app and updater on `windows-latest`, creates or updates GitHub Release `v1.0.1`, and uploads `SerpiumVPN-1.0.1.zip` plus `update.json`. You can also start the same workflow manually from GitHub Actions with `Run workflow` and enter the version.

## Repository Layout

- `MainWindow.xaml` / `MainWindow.xaml.cs` - main desktop UI.
- `TelegramProxyManager.cs` - Telegram Desktop proxy mode.
- `VendorUpdateManager.cs` - Telegram WS Proxy updates.
- `bin_files/relay`, `bin_files/tgws`, `bin_files/wfp` - bundled networking components.
- `licenses/` - third-party license texts.
- `THIRD_PARTY_NOTICES.txt` - attribution and component summary.

## Third-party Components

SerpiumVPN uses and/or may be distributed with third-party components, including:

- Flowseal/tg-ws-proxy
- SagerNet/sing-box
- XTLS/Xray-core

These projects belong to their respective authors. SerpiumVPN is not affiliated with Flowseal, SagerNet, XTLS, Telegram, YouTube, Discord, or Google.

See `THIRD_PARTY_NOTICES.txt` and the `licenses/` directory for license details and attribution.

## License

SerpiumVPN source code is licensed under the MIT License. Third-party components remain under their own licenses.
