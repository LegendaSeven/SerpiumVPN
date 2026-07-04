# SerpiumVPN

SerpiumVPN is a Windows desktop application for running local bypass/proxy profiles for selected services. The project is built as a WPF app on .NET and wraps several third-party networking components behind a simple desktop interface.

## Features

- Windows WPF interface for starting and stopping profiles.
- Built-in profiles and lists for YouTube, Discord, Google, and custom domains.
- Telegram Desktop WS/MTProto local proxy mode.
- Vendor update flow for bundled third-party components.
- Third-party license and attribution files included in the repository.

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
- `ZapretManager.cs` - winws/zapret process and profile control.
- `TelegramProxyManager.cs` - Telegram Desktop proxy mode.
- `VendorUpdateManager.cs` - update flow for bundled vendor binaries.
- `bin_files/` - runtime files, profiles, lists, and bundled third-party binaries.
- `licenses/` - third-party license texts.
- `THIRD_PARTY_NOTICES.txt` - attribution and component summary.

## Third-party Components

SerpiumVPN uses and/or may be distributed with third-party components, including:

- Flowseal/tg-ws-proxy
- Flowseal/zapret-discord-youtube
- bol-van/zapret
- basil00/WinDivert

These projects belong to their respective authors. SerpiumVPN is not affiliated with Flowseal, bol-van, WinDivert, Telegram, YouTube, Discord, or Google.

See `THIRD_PARTY_NOTICES.txt` and the `licenses/` directory for license details and attribution.

## License

SerpiumVPN source code is licensed under the MIT License. Third-party components remain under their own licenses.
