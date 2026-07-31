using System;
using System.Collections.Generic;
using System.Linq;
using SerpiumVPN.Core.Interfaces;

namespace SerpiumVPN.Core;

/// <summary>
/// Stores the components known to the Serpium platform during the current process lifetime.
/// </summary>
public sealed class ComponentRegistry
{
    private readonly List<IComponent> _components = new();

    public IReadOnlyList<IComponent> Components => _components.AsReadOnly();

    public int Count => _components.Count;

    public void Register(IComponent component)
    {
        ArgumentNullException.ThrowIfNull(component);

        if (_components.Any(existing =>
                string.Equals(existing.Info.Name, component.Info.Name, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException(
                $"Component '{component.Info.Name}' is already registered.");
        }

        _components.Add(component);
    }

    public bool TryGet(string name, out IComponent? component)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            component = null;
            return false;
        }

        component = _components.FirstOrDefault(existing =>
            string.Equals(existing.Info.Name, name, StringComparison.OrdinalIgnoreCase));

        return component is not null;
    }

    public IReadOnlyList<IComponent> GetByType(ComponentType type)
    {
        return _components
            .Where(component => component.Info.Type == type)
            .ToArray();
    }
}
