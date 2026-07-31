using System.Threading.Tasks;

namespace SerpiumVPN.Core.Interfaces;

/// <summary>
/// Contract implemented by every connection engine loaded by Serpium.
/// </summary>
public interface IEngine : IComponent
{
    bool IsConnected { get; }

    Task ConnectAsync();

    Task DisconnectAsync();
}
