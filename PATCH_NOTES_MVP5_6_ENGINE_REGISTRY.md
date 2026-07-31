# SerpiumVPN MVP5.6 — Engine Registry

## Added

- `Core/Registry/EngineRegistry.cs`
- Engine registration through the shared `ComponentRegistry`
- Engine lookup by name
- Required-engine lookup with a clear exception
- Lists of enabled and connected engines
- Validation that every registered `IEngine` declares `ComponentType.Engine`

## Changed

- `PlatformRuntime` now exposes `EngineRegistry`
- `PlatformBootstrap` creates and wires both registries
- `PlatformBootstrap.Create` accepts an optional engine configuration callback
- Runtime startup log now includes the number of registered engines

## Compatibility

- Relay, Headscale, SerpiumNet and WPF startup are not changed in this MVP.
- No engine is registered automatically yet.
- Existing component lifecycle remains managed by `ComponentLoader`.

## Completion criteria

- Project builds with 0 errors.
- `Core/Registry/EngineRegistry.cs` exists.
- `PlatformRuntime.EngineRegistry` is available.
- Existing application behavior remains unchanged.
