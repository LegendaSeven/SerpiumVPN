using System.Threading.Tasks;

namespace SerpiumVPN.Core.Interfaces;

/// <summary>
/// Base lifecycle contract for a Serpium platform component.
/// </summary>
public interface IComponent
{
    ComponentInfo Info { get; }

    ComponentState State { get; }

    Task InitializeAsync();

    Task ShutdownAsync();
}
