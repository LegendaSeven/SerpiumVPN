# Serpium Sample Engine

This package is the smoke test for the dynamic engine pipeline.

MVP5.9 changes the sample from a reference to the complete WPF application into
a reference to the platform-neutral SDK project:

```text
Serpium.SampleEngine
        ↓
Serpium.Engine.Abstractions
        ↑
SerpiumVPN
```

The engine now targets plain `net10.0`. It does not reference `SerpiumVPN.dll`,
WPF, Windows Forms or `WindowsBase`.

The shared SDK DLL is supplied by the Serpium host. It is deliberately not copied
inside the engine package, so the host and the engine use one contract assembly
and one `IEngine` type identity.
