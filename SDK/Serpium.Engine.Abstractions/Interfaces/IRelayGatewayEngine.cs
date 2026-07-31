using System;
using System.Threading;
using System.Threading.Tasks;

namespace SerpiumVPN.Core.Interfaces;

/// <summary>
/// Optional capability implemented by engines that can expose a Relay gateway.
/// The contract contains no UI dependencies, so external engines remain platform-neutral.
/// </summary>
public interface IRelayGatewayEngine : IEngine
{
    bool HasLiveGatewayProcess { get; }

    Task<RelayGatewayStartResult> StartGatewayAsync(
        int port,
        IProgress<RelayGatewayEvent>? progress = null,
        CancellationToken cancellationToken = default);

    Task StopGatewayAsync();
}
