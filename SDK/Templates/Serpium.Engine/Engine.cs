using SerpiumVPN.Core;
using SerpiumVPN.Core.Interfaces;

namespace Serpium.Engine.Template;

/// <summary>
/// External Serpium engine entry point.
/// Keep this type public, non-abstract and equipped with a public parameterless constructor.
/// </summary>
public sealed class Engine : IEngine
{
    public ComponentInfo Info { get; } = new()
    {
        Name = "Serpium.Engine.Template",
        Version = "1.0.0",
        Type = ComponentType.Engine
    };

    public ComponentState State { get; private set; } = ComponentState.Disabled;

    public bool IsConnected { get; private set; }

    public Task InitializeAsync()
    {
        State = ComponentState.Enabled;
        return Task.CompletedTask;
    }

    public Task ShutdownAsync()
    {
        IsConnected = false;
        State = ComponentState.Disabled;
        return Task.CompletedTask;
    }

    public Task ConnectAsync()
    {
        if (State != ComponentState.Enabled)
        {
            throw new InvalidOperationException(
                "The engine must be initialized before connecting.");
        }

        IsConnected = true;
        return Task.CompletedTask;
    }

    public Task DisconnectAsync()
    {
        IsConnected = false;
        return Task.CompletedTask;
    }
}
