# SerpiumVPN MVP5.10 — Engine Template & Packager

## Goal

Make new external engines reproducible instead of assembling every module by
hand. This patch adds a native `dotnet new` template, a source workspace and one
packager that validates, builds, installs and archives an engine.

## Added

```text
SDK/
├── Templates/Serpium.Engine/
│   ├── .template.config/template.json
│   ├── Serpium.Engine.Template.csproj
│   ├── Engine.cs
│   ├── manifest.json
│   ├── build-engine.ps1
│   └── README.md
├── Tools/
│   ├── Install-SerpiumEngineTemplate.ps1
│   ├── New-SerpiumEngine.ps1
│   └── Build-SerpiumEngine.ps1
├── Workspace/
└── Packages/
```

## Template workflow

Install the template once:

```powershell
.\SDK\Tools\Install-SerpiumEngineTemplate.ps1
```

Create an engine through .NET CLI:

```powershell
Set-Location .\SDK\Workspace
dotnet new serpium-engine -n MyEngine
```

Equivalent helper from the repository root:

```powershell
.\SDK\Tools\New-SerpiumEngine.ps1 -Name MyEngine
```

The helper automatically installs or refreshes the local template and writes the
source into `SDK/Workspace/MyEngine`.

## Packaging workflow

From a generated project:

```powershell
.\build-engine.ps1
```

The packager:

1. finds the SerpiumVPN repository and current SDK contract;
2. validates `schemaVersion`, `apiVersion`, package id, entry type and DLL path;
3. builds the engine with only `Serpium.Engine.Abstractions` as the host contract;
4. resolves the actual MSBuild `TargetPath`;
5. copies the DLL, `.deps.json`, managed dependencies and native files;
6. excludes the host-provided `Serpium.Engine.Abstractions.*` files;
7. installs the package to `Engines/<engine-id>/Runtime`;
8. writes a runtime manifest whose assembly path points into `Runtime`;
9. creates `SDK/Packages/<engine-id>-v<version>.zip`.

## Generated package format

```text
Engines/
└── serpium.MyEngine/
    ├── manifest.json
    └── Runtime/
        ├── MyEngine.dll
        ├── MyEngine.deps.json
        └── dependencies...
```

The existing DynamicEngineLoader already supports the relative
`Runtime/MyEngine.dll` assembly path, so no Core or application lifecycle change
is required in MVP5.10.

## Safety

- invalid or incompatible manifests stop packaging before installation;
- package ids use the same character rules as DynamicEngineLoader;
- absolute paths and `..` traversal are rejected;
- package replacement is staged in a temporary directory;
- source projects remain separate under `SDK/Workspace`;
- the shared SDK DLL is not duplicated inside engine packages.

## Verification

After applying the patch, run:

```powershell
.\SDK\Tools\New-SerpiumEngine.ps1 -Name TemplateSmoke
.\SDK\Workspace\TemplateSmoke\build-engine.ps1 -Configuration Debug
```

Expected outputs:

```text
Engines/serpium.TemplateSmoke/manifest.json
Engines/serpium.TemplateSmoke/Runtime/TemplateSmoke.dll
SDK/Packages/serpium.TemplateSmoke-v1.0.0.zip
```

Restart SerpiumVPN. The runtime log should show the new package as loaded and
initialized. Remove the smoke-test package afterward if it is no longer needed.
