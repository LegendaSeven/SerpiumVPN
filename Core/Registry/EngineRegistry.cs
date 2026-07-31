using System;
using System.Collections.Generic;
using System.Linq;
using SerpiumVPN.Core.Interfaces;

namespace SerpiumVPN.Core;

/// <summary>
/// Provides engine-specific access to components registered in the platform runtime.
/// </summary>
public sealed class EngineRegistry
{
    private readonly ComponentRegistry _componentRegistry;

    public EngineRegistry(ComponentRegistry componentRegistry)
    {
        _componentRegistry = componentRegistry
            ?? throw new ArgumentNullException(nameof(componentRegistry));
    }

    public IReadOnlyList<IEngine> Engines => _componentRegistry.Components
        .OfType<IEngine>()
        .ToArray();

    public int Count => Engines.Count;

    public void Register(IEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);

        if (engine.Info.Type != ComponentType.Engine)
        {
            throw new InvalidOperationException(
                $"Component '{engine.Info.Name}' implements IEngine but declares type '{engine.Info.Type}'.");
        }

        _componentRegistry.Register(engine);
    }

    public bool TryGet(string name, out IEngine? engine)
    {
        if (!_componentRegistry.TryGet(name, out IComponent? component) ||
            component is not IEngine registeredEngine)
        {
            engine = null;
            return false;
        }

        engine = registeredEngine;
        return true;
    }

    public IEngine GetRequired(string name)
    {
        if (!TryGet(name, out IEngine? engine) || engine is null)
        {
            throw new KeyNotFoundException(
                $"Engine '{name}' is not registered in the Serpium platform runtime.");
        }

        return engine;
    }

    public IReadOnlyList<IEngine> GetEnabled()
    {
        return Engines
            .Where(engine => engine.State == ComponentState.Enabled)
            .ToArray();
    }

    public IReadOnlyList<IEngine> GetConnected()
    {
        return Engines
            .Where(engine => engine.IsConnected)
            .ToArray();
    }
}
