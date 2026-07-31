# SerpiumVPN MVP6.1 — Relay → External Engine Bridge

## Goal

Move the real SerpiumNet Relay gateway process lifecycle out of the WPF host and
into the dynamically loaded external engine without changing the existing Relay
UI call surface.

## Added

### Engine SDK

- `IRelayGatewayEngine`
- `RelayGatewayEventKind`
- `RelayGatewayEvent`
- `RelayGatewayStartResult`

These contracts are UI-neutral and remain inside
`Serpium.Engine.Abstractions.dll`.

### Host runtime bridge

- `PlatformRuntimeHost`

`App.xaml.cs` attaches the active `PlatformRuntime` during startup and detaches
it during shutdown. Legacy WPF adapters can therefore resolve loaded engines
without making external engines depend on WPF.

## Changed

### `Relay/SerpiumNetManager.cs`

The public API remains compatible:

```csharp
Task<string> StartGatewayAsync(Window owner, int port, CancellationToken token)
Task StopAsync()
bool HasLiveProcess
```

Internally it now:

1. resolves the dynamically loaded `SerpiumNet` engine from `EngineRegistry`;
2. requires the optional `IRelayGatewayEngine` capability;
3. forwards gateway startup and shutdown to the external engine;
4. translates UI-neutral authorization events into the existing WPF auth
   window;
5. no longer starts `bin_files/relay/SerpiumNet.exe` directly.

### `SerpiumNetAuthWindow.xaml.cs`

Cancellation is emitted only once when the button closes the window, preventing
repeated stop requests.

### External SerpiumNet engine 0.4.1

The engine now owns:

- `SerpiumNet.exe gateway ...` process startup;
- stdout/stderr parsing;
- `LOGIN_URL` authorization reporting;
- `TAILSCALE_IP` address reporting;
- `GATEWAY_READY` completion;
- process cancellation and shutdown;
- engine-side logging.

The native binary itself remains `SerpiumNet 0.4.0-mvp4-persistent-node`; version
`0.4.1` identifies the updated external engine wrapper/package.

## Expected architecture after the patch

```text
Existing Relay UI
        ↓
SerpiumNetManager (WPF adapter)
        ↓
PlatformRuntimeHost
        ↓
EngineRegistry
        ↓
IRelayGatewayEngine
        ↓
Serpium.SerpiumNet.Engine.dll
        ↓
Engines/serpium.SerpiumNet/Runtime/SerpiumNet.exe
```

## Build verification

Expected result:

- 0 build errors;
- the existing `CS4014` warning in `Relay/SerpiumNetManager.cs` should no longer
  originate from the replaced manager; any remaining `CS4014` must be checked by
  its reported file and line;
- external package version in the runtime log: `SerpiumNet 0.4.1`.

## Runtime verification

1. Start SerpiumVPN normally.
2. Start the existing SerpiumNet Relay/gateway flow from the UI.
3. Complete authorization if the login window appears.
4. Confirm that the Relay flow receives a virtual address and becomes ready.
5. Stop Relay, then exit SerpiumVPN through the tray.

Expected engine log:

```text
Initialized. Binary=SerpiumNet 0.4.0-mvp4-persistent-node
Gateway process started. Port=<port>.
stdout: TAILSCALE_IP=<virtual-ip>
stdout: GATEWAY_READY=<port>
Gateway ready. Address=<virtual-ip>; Port=<port>.
Gateway stopped.
Shutdown completed.
```

On first authorization, this line should also appear:

```text
stdout: LOGIN_URL=https://...
```

Logs:

```text
%LOCALAPPDATA%\SerpiumVPN\Logs\platform-runtime.log
%LOCALAPPDATA%\SerpiumVPN\Logs\serpium-net-engine.log
```

## Rollback

Restore the files changed by this patch from the previous working archive/tag,
then rebuild the MVP6.0 engine package and the main project.
