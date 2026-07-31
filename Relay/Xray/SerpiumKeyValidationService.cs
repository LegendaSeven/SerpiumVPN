using System.Diagnostics;
using System.Net.Sockets;
using SerpiumVPN.Relay.Parser;
using System.IO;

namespace SerpiumVPN.Relay.Xray;

public sealed class SerpiumKeyValidationService
{
    public async Task<SerpiumKeyValidationResult> ValidateAsync(
        string xrayPath,
        SerpiumConnectionProfile profile,
        int socksPort,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(xrayPath))
        {
            throw new FileNotFoundException(
                "xray.exe не найден в bin_files\\relay.",
                xrayPath);
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "SerpiumVPN", "KeyValidation");
        Directory.CreateDirectory(tempRoot);
        string tempConfig = Path.Combine(tempRoot, "validate-" + Guid.NewGuid().ToString("N") + ".json");
        string tempLog = Path.Combine(tempRoot, "logs");
        Directory.CreateDirectory(tempLog);

        try
        {
            string json = SerpiumXrayConfigBuilder.Build(profile, socksPort, tempLog);
            await File.WriteAllTextAsync(tempConfig, json, cancellationToken);

            (bool configValid, string configMessage) = await ValidateConfigAsync(
                xrayPath,
                tempConfig,
                cancellationToken);

            if (!configValid)
            {
                return new SerpiumKeyValidationResult
                {
                    ConfigValid = false,
                    ServerReachable = false,
                    Message = configMessage
                };
            }

            bool reachable = await CanConnectAsync(
                profile.Server,
                profile.Port,
                TimeSpan.FromSeconds(6),
                cancellationToken);

            return new SerpiumKeyValidationResult
            {
                ConfigValid = true,
                ServerReachable = reachable,
                Message = reachable
                    ? "Конфигурация Xray корректна, сервер принимает TCP-соединение."
                    : "Конфигурация Xray корректна, но сервер не ответил на проверку TCP."
            };
        }
        finally
        {
            try { File.Delete(tempConfig); } catch { }
        }
    }

    private static async Task<(bool Success, string Message)> ValidateConfigAsync(
        string xrayPath,
        string configPath,
        CancellationToken cancellationToken)
    {
        ProcessStartInfo info = new()
        {
            FileName = xrayPath,
            WorkingDirectory = Path.GetDirectoryName(xrayPath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-test");
        info.ArgumentList.Add("-config");
        info.ArgumentList.Add(configPath);

        using Process process = new() { StartInfo = info };
        if (!process.Start())
            return (false, "Не удалось запустить проверку Xray-конфигурации.");

        Task<string> outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));

        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return (false, "Проверка Xray-конфигурации превысила 10 секунд.");
        }

        string output = (await outputTask).Trim();
        string error = (await errorTask).Trim();
        if (process.ExitCode == 0)
            return (true, "Конфигурация Xray корректна.");

        string message = string.IsNullOrWhiteSpace(error) ? output : error;
        if (string.IsNullOrWhiteSpace(message))
            message = $"Xray отклонил конфигурацию с кодом {process.ExitCode}.";

        return (false, SanitizeMessage(message));
    }

    private static async Task<bool> CanConnectAsync(
        string host,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using TcpClient client = new();
        using CancellationTokenSource timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            await client.ConnectAsync(host, port, timeoutSource.Token);
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static string SanitizeMessage(string message)
    {
        string oneLine = string.Join(
            " ",
            message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries));
        return oneLine.Length <= 500 ? oneLine : oneLine[..500] + "…";
    }
}
