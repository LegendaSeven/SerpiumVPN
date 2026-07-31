# SerpiumVPN MVP6.0 — SerpiumNet External Engine

## Goal

Package the existing SerpiumNet native executable as the first real external
Serpium engine without changing the currently working Relay path.

## Added

```text
SDK/Workspace/SerpiumNetEngine/
├── Serpium.SerpiumNet.Engine.csproj
├── SerpiumNetEngine.cs
├── manifest.json
├── build-engine.ps1
└── README.md
```

The engine package produced by the existing MVP5.10 packager is:

```text
Engines/serpium.SerpiumNet/
├── manifest.json
└── Runtime/
    ├── Serpium.SerpiumNet.Engine.dll
    ├── Serpium.SerpiumNet.Engine.deps.json
    └── SerpiumNet.exe
```

## Runtime behavior

- DynamicEngineLoader discovers `serpium.SerpiumNet` like any other engine.
- `InitializeAsync` runs `SerpiumNet.exe version` and only enables the engine if
  the native binary starts successfully and returns the expected response.
- `ShutdownAsync` terminates an engine-owned SerpiumNet process safely.
- `ConnectAsync` supports the persistent `node` command as an isolated engine
  lifecycle foundation. Authentication UI is intentionally deferred to the
  Relay-to-Engine bridge.
- Engine diagnostics are written to:
  `%LOCALAPPDATA%\SerpiumVPN\Logs\serpium-net-engine.log`.

## Not changed

- `Relay/SerpiumNetManager.cs`
- `Relay/SerpiumNetAuthWindow.*`
- current Relay UI and connection behavior
- the Go source or compiled `SerpiumNet.exe`

This keeps the existing working path intact while proving that SerpiumNet can be
built, packaged and initialized as an independent engine.

## Expected verification

After applying the patch and launching SerpiumVPN, `platform-runtime.log` should
contain an additional package and component:

```text
[Engines] Loaded: id=serpium.SerpiumNet; name=SerpiumNet; version=0.4.0.
[Components] Initializing: SerpiumNet 0.4.0
[Components] Loaded: SerpiumNet
```

The summary should report three engines if SampleEngine and TemplateSmoke are
still installed:

```text
packages=3
loaded=3
failed=0
Engines=3
```
