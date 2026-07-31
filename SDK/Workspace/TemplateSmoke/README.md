# TemplateSmoke

This project was generated from the official `serpium-engine` template.

## Build and install

From this directory:

```powershell
.\build-engine.ps1
```

The script:

1. validates `manifest.json` against the current Serpium Engine API;
2. builds the engine without linking it to the WPF host;
3. copies the DLL and runtime dependencies into `SerpiumVPN/Engines/<engine-id>`;
4. creates a distributable ZIP under `SDK/Packages`.

Use `-Configuration Debug` while developing and `-NoZip` when only a local
installation is needed.

## Contract rules

The entry class must:

- implement `SerpiumVPN.Core.Interfaces.IEngine`;
- be public and non-abstract;
- expose a public parameterless constructor;
- return `ComponentType.Engine` from `Info.Type`.

Keep the version in `Engine.cs` and `manifest.json` synchronized.
