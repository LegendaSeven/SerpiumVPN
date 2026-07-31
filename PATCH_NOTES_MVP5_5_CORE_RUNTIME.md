# SerpiumVPN MVP5.5 — Core Runtime

## Added

- `PlatformRuntime` — central lifecycle coordinator for the platform.
- `PlatformRuntimeState` — explicit runtime state model.
- `PlatformRuntimeStartResult` — startup result with component initialization summary.
- `PlatformBootstrap` — composition root for creating the registry, loader, and runtime.

## Behavior

- Starts all registered components through the existing `ComponentLoader`.
- Stops components in reverse order through the existing loader.
- Protects startup and shutdown with an asynchronous lifecycle lock.
- Supports repeated safe calls to start/stop.
- Does not yet modify `App.xaml.cs` or current Relay behavior.

## Scope

This patch adds runtime infrastructure only. WPF startup integration and concrete engines remain deferred to later MVPs.

## Verification

1. Apply the patch.
2. Clean `bin` and `obj`.
3. Build `SerpiumVPN.csproj`.
4. Expected result: 0 new build errors.
