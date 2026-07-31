# SerpiumVPN MVP6.1.1 — Tailscale Login Flow

## Goal

Fix first-run SerpiumNet authorization when `tsnet` prints its temporary login
URL to `stderr` as human-readable text instead of (or in addition to) the
machine-readable `LOGIN_URL=...` line.

This patch keeps the MVP6.1 Relay → external engine bridge and changes only the
authorization flow around it.

## Confirmed problem

The external process was started from the correct package path:

```text
bin\Debug\net10.0-windows\Engines\serpium.SerpiumNet\Runtime\SerpiumNet.exe
```

However, the live process repeatedly emitted this form through `stderr`:

```text
To start this tsnet server ... go to: https://login.tailscale.com/a/...
```

MVP6.1 parsed authorization URLs only from `stdout` lines beginning with
`LOGIN_URL=`. The WPF adapter also created the authorization window without
calling `Show()`. As a result, the Relay page remained at “подключение” while
no visible login flow appeared.

## Changed

### External SerpiumNet engine 0.4.2

`SerpiumNetEngine.cs` now:

- sends both `stdout` and `stderr` through one protocol parser;
- recognizes both formats:
  - `LOGIN_URL=https://login.tailscale.com/a/...`
  - arbitrary `tsnet` text containing the same trusted URL;
- validates that the URL uses HTTPS, the exact host `login.tailscale.com`, and
  the `/a/` authorization path;
- reports `AuthorizationRequired` only for a newly observed URL;
- redacts temporary login URLs from `serpium-net-engine.log`;
- preserves the actual URL only in memory for the local authorization window;
- fixes reuse of an already captured authorization URL in node mode.

Package/engine wrapper version:

```text
0.4.2
```

The native binary remains:

```text
SerpiumNet 0.4.0-mvp4-persistent-node
```

### Relay authorization window

`SerpiumNetManager.cs` now explicitly shows and activates the auth window.

`SerpiumNetAuthWindow.xaml.cs` now:

- opens the Tailscale login page automatically once;
- keeps manual “Открыть страницу входа” and “Скопировать ссылку” controls;
- explains that the running connection continues automatically after approval;
- does not reopen the same temporary URL repeatedly;
- shows a local error if Windows cannot launch the browser.

## Expected first-run flow

```text
Relay: Запустить шлюз
        ↓
External SerpiumNet.exe starts
        ↓
Login URL captured from stdout or stderr
        ↓
Authorization window becomes visible
        ↓
Default browser opens once
        ↓
User approves the device
        ↓
TAILSCALE_IP + GATEWAY_READY
        ↓
Relay gateway becomes ready and the auth window closes
```

## Build verification

Expected:

- `Serpium.SerpiumNet.Engine` package version `0.4.2`;
- 0 build errors;
- existing unrelated warnings may remain unchanged.

## Runtime verification

1. Fully exit SerpiumVPN through the tray and stop Visual Studio debugging.
2. Apply the patch and build.
3. Start SerpiumVPN.
4. Open **Serpium Relay** and press **Запустить шлюз**.
5. On a first authorization, confirm:
   - a SerpiumNet authorization window appears;
   - the default browser opens automatically;
   - after approval, the gateway reaches ready state.
6. Stop the gateway and exit through the tray.

Expected engine log fragments:

```text
Initialized. Binary=SerpiumNet 0.4.0-mvp4-persistent-node
Gateway process started. Port=<port>.
stderr: ... <tailscale-login-url-redacted>
Authorization URL captured from SerpiumNet output (redacted in logs).
stdout: LOGIN_OK
stdout: TAILSCALE_IP=<virtual-address>
stdout: GATEWAY_READY=<port>
Gateway ready. Address=<virtual-address>; Port=<port>.
Gateway stopped.
```

The full temporary Tailscale login URL should no longer be written to the
engine log.

Logs:

```text
%LOCALAPPDATA%\SerpiumVPN\Logs\platform-runtime.log
%LOCALAPPDATA%\SerpiumVPN\Logs\serpium-net-engine.log
```

## Rollback

Restore these files from the MVP6.1 working version and rebuild:

```text
Relay\SerpiumNetManager.cs
Relay\SerpiumNetAuthWindow.xaml.cs
SDK\Workspace\SerpiumNetEngine\SerpiumNetEngine.cs
SDK\Workspace\SerpiumNetEngine\Serpium.SerpiumNet.Engine.csproj
SDK\Workspace\SerpiumNetEngine\manifest.json
```
