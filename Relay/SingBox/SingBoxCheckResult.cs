namespace SerpiumVPN.Relay.SingBox;

internal sealed class SingBoxCheckResult
{
    private SingBoxCheckResult(
        bool success,
        string engineVersion,
        int exitCode,
        string message)
    {
        Success = success;
        EngineVersion = string.IsNullOrWhiteSpace(engineVersion)
            ? "sing-box"
            : engineVersion.Trim();
        ExitCode = exitCode;
        Message = string.IsNullOrWhiteSpace(message)
            ? (success
                ? "Конфигурация принята движком."
                : "Движок отклонил конфигурацию.")
            : message.Trim();
    }

    public bool Success { get; }
    public string EngineVersion { get; }
    public int ExitCode { get; }
    public string Message { get; }

    public static SingBoxCheckResult Accepted(
        string engineVersion,
        string message) =>
        new(true, engineVersion, 0, message);

    public static SingBoxCheckResult Rejected(
        string engineVersion,
        int exitCode,
        string message) =>
        new(false, engineVersion, exitCode, message);
}
