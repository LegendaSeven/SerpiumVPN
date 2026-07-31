using System;
using System.IO;

namespace SerpiumVPN.Core;

/// <summary>
/// Creates a fully wired platform runtime without coupling it to WPF startup code.
/// </summary>
public static class PlatformBootstrap
{
    public static PlatformRuntime Create(
        Action<ComponentRegistry>? configureComponents = null,
        Action<EngineRegistry>? configureEngines = null,
        Action<string>? log = null,
        string? engineDirectory = null)
    {
        var componentRegistry = new ComponentRegistry();
        var engineRegistry = new EngineRegistry(componentRegistry);

        configureComponents?.Invoke(componentRegistry);
        configureEngines?.Invoke(engineRegistry);

        var componentLoader = new ComponentLoader(componentRegistry, log);
        var dynamicEngineLoader = new DynamicEngineLoader(
            engineRegistry,
            engineDirectory ?? Path.Combine(AppContext.BaseDirectory, "Engines"),
            log);

        return new PlatformRuntime(
            componentRegistry,
            engineRegistry,
            componentLoader,
            dynamicEngineLoader,
            log);
    }
}
