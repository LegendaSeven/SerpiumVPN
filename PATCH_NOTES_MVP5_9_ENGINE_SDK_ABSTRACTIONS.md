# SerpiumVPN MVP5.9 — Engine SDK / Abstractions

## Goal

Detach external engines from the complete WPF application and establish one
platform-neutral contract assembly shared by the host and every engine.

## Added

```text
SDK/
├── README.md
└── Serpium.Engine.Abstractions/
    ├── Serpium.Engine.Abstractions.csproj
    ├── EngineContract.cs
    ├── Interfaces/
    │   ├── IComponent.cs
    │   ├── IEngine.cs
    │   ├── IFeature.cs
    │   └── IService.cs
    └── Models/
        ├── ComponentInfo.cs
        ├── ComponentState.cs
        └── ComponentType.cs
```

The SDK targets plain `net10.0` and has no UI or Windows desktop dependency.

## Migrated contracts

The contract source files are removed from the WPF project and compiled only by
`Serpium.Engine.Abstractions`:

- `Core/Interfaces/IComponent.cs`
- `Core/Interfaces/IEngine.cs`
- `Core/Interfaces/IFeature.cs`
- `Core/Interfaces/IService.cs`
- `Core/Models/ComponentInfo.cs`
- `Core/Models/ComponentState.cs`
- `Core/Models/ComponentType.cs`
- `Core/Models/EngineContract.cs`

Their existing namespaces are preserved intentionally, so current Core code does
not require a mass namespace rewrite.

## Main application changes

- `SerpiumVPN.csproj` references the SDK project.
- SDK source files are excluded from the parent WPF project's default globbing.
- `Serpium.Engine.Abstractions.dll` is copied to the application output through
  the project reference.
- The Sample Engine build no longer receives `SerpiumVPN.dll` as a contract.

## Sample Engine changes

- targets `net10.0` instead of `net10.0-windows`;
- references only `Serpium.Engine.Abstractions`;
- no longer references the WPF host;
- does not copy the SDK into its package (`Private=false`), because the loader
  shares the host SDK assembly to preserve one `IEngine` type identity.

## Expected build result

The main output should contain:

```text
bin/Debug/net10.0-windows/
├── SerpiumVPN.dll
├── Serpium.Engine.Abstractions.dll
└── Engines/SampleEngine/
    ├── manifest.json
    └── Serpium.SampleEngine.dll
```

The previous Sample Engine `MSB3277 WindowsBase` conflict should disappear.
The existing unrelated `CS4014` warning in `Relay/SerpiumNetManager.cs` may remain.

## Runtime verification

Start SerpiumVPN, then exit through the tray menu. The platform log should still
show:

```text
[Engines] Loaded: id=serpium.sample
[Components] Loaded: Serpium Sample Engine
[Components] Shutting down: Serpium Sample Engine
[Runtime] Serpium platform stopped.
```
