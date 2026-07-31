namespace SerpiumVPN.Core;

/// <summary>
/// Current lifecycle state of the Serpium platform runtime.
/// </summary>
public enum PlatformRuntimeState
{
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
    Faulted
}
