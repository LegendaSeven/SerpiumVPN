# Serpium Engine SDK

`Serpium.Engine.Abstractions` is the platform-neutral contract assembly shared by
SerpiumVPN and external engine DLLs.

The assembly contains only public contracts and metadata:

- `IComponent`
- `IEngine`
- `IRelayGatewayEngine` (optional Relay gateway capability)
- `IFeature`
- `IService`
- `ComponentInfo`
- `ComponentState`
- `ComponentType`
- `EngineContract`

It targets `net10.0` and has no WPF, Windows Forms, `WindowsBase`, Relay or
SerpiumVPN application dependency.

The existing `SerpiumVPN.Core` namespaces are intentionally preserved in MVP5.9.
That keeps current Core code and early engines source-compatible while moving the
actual type identity into `Serpium.Engine.Abstractions.dll`.

## Engine template and packager

MVP5.10 adds the official `serpium-engine` template and packaging tools.

Install the template once:

```powershell
.\SDK\Tools\Install-SerpiumEngineTemplate.ps1
```

Then create a project with the native .NET template command:

```powershell
Set-Location .\SDK\Workspace
dotnet new serpium-engine -n MyEngine
```

Or use the helper from the repository root:

```powershell
.\SDK\Tools\New-SerpiumEngine.ps1 -Name MyEngine
```

Build, validate, package and install the generated engine:

```powershell
.\SDK\Workspace\MyEngine\build-engine.ps1
```

Ready packages are installed under `Engines/<engine-id>` and distributable ZIPs
are written to `SDK/Packages`.

## Optional Relay gateway capability

MVP6.1 adds `IRelayGatewayEngine`. Engines that implement it can be consumed by
the existing Relay UI without giving the engine a WPF dependency. Authorization,
address assignment, readiness and failures are delivered through
`RelayGatewayEvent`, while `RelayGatewayStartResult` returns the virtual address
and listening port.
