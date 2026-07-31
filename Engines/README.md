# External Serpium engines

Each external engine is distributed as a separate directory:

```text
Engines/
└── serpium.MyEngine/
    ├── manifest.json
    └── Runtime/
        ├── MyEngine.dll
        ├── MyEngine.deps.json
        └── dependency.dll
```

Required `manifest.json` fields:

- `schemaVersion`: currently `1`
- `id`: stable package identifier; letters, digits, `.`, `-`, `_`
- `apiVersion`: currently `1`
- `assembly`: engine DLL path relative to the package directory
- `enabled`: optional, defaults to `true`
- `entryType`: optional full type name; required when the DLL contains multiple `IEngine` implementations

The engine project must reference `SDK/Serpium.Engine.Abstractions/Serpium.Engine.Abstractions.csproj`
(or a future packaged SDK release), not `SerpiumVPN.dll`.

The engine class must:

- implement `SerpiumVPN.Core.Interfaces.IEngine` from `Serpium.Engine.Abstractions.dll`;
- be public and non-abstract;
- expose a public parameterless constructor;
- return `ComponentType.Engine` from `Info.Type`.

A broken or incompatible engine is logged and skipped. It does not terminate the
platform runtime.

## Creating engines

The official template and packager live under `SDK`:

```powershell
.\SDK\Tools\New-SerpiumEngine.ps1 -Name MyEngine
.\SDK\Workspace\MyEngine\build-engine.ps1
```

The packager validates the manifest against the current Engine API, excludes the
host-provided `Serpium.Engine.Abstractions.dll`, installs the package here and
creates a distributable ZIP under `SDK/Packages`.

## First production engine: SerpiumNet

The source wrapper for the first real external engine lives at:

```text
SDK/Workspace/SerpiumNetEngine
```

Its package contains both the managed engine adapter and the native
`SerpiumNet.exe`. Starting with MVP6.1, the existing Relay WPF adapter resolves
this package through `EngineRegistry` and uses the optional
`IRelayGatewayEngine` capability instead of starting a second embedded binary
directly.
