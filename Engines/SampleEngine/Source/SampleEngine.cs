using System.Threading.Tasks;
using SerpiumVPN.Core;
using SerpiumVPN.Core.Interfaces;

namespace Serpium.SampleEngine;

/// <summary>
/// One-time smoke-test engine proving that an external DLL can be discovered,
/// instantiated, registered, initialized and shut down through the platform runtime.
/// </summary>
public sealed class SampleEngine : IEngine
{
    public ComponentInfo Info { get; } = new()
    {
        Name = "Serpium Sample Engine",
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
                "The sample engine must be initialized before connecting.");
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
