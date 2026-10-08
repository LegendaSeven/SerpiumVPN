using System.Diagnostics;
using System.Security.Cryptography;
using IOPath = System.IO.Path;
using System.Text;
using System.Text.RegularExpressions;
using SerpiumVPN.Relay.Providers;

namespace SerpiumVPN.Relay.SingBox;

/// <summary>
/// Validates an in-memory provider configuration with the bundled sing-box CLI.
/// The configuration is supplied through stdin and is never written to disk.
/// Raw engine output is never returned to the UI without conservative redaction.
/// </summary>
internal sealed partial class SerpiumSingBoxValidationService
{
    private static readonly TimeSpan VersionTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(20);

    public async Task<SingBoxCheckResult> ValidateAsync(
        string singBoxExecutablePath,
        ProviderRuntimeProfile runtimeProfile,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(singBoxExecutablePath))
            throw new ArgumentException("Путь к sing-box не указан.", nameof(singBoxExecutablePath));
        ArgumentNullException.ThrowIfNull(runtimeProfile);
        cancellationToken.ThrowIfCancellationRequested();

        string executablePath = IOPath.GetFullPath(singBoxExecutablePath);
        if (!System.IO.File.Exists(executablePath))
        {
            return SingBoxCheckResult.Rejected(
                "sing-box",
                -1,
                "Движок sing-box не найден в bin_files\\relay. Повторно примените патч MVP7.0A.5.3.");
        }

        string engineVersion = await ReadEngineVersionAsync(
            executablePath,
            cancellationToken);

        byte[] configurationUtf8 = runtimeProfile.CopyConfiguration();
        try
        {
            return await RunCheckAsync(
                executablePath,
                engineVersion,
                configurationUtf8,
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(configurationUtf8);
        }
    }

    private static async Task<string> ReadEngineVersionAsync(
        string executablePath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProcessStartInfo startInfo = CreateBaseStartInfo(executablePath);
        startInfo.ArgumentList.Add("version");
        startInfo.ArgumentList.Add("--disable-color");

        using Process process = new() { StartInfo = startInfo };
        if (!process.Start())
            return "sing-box (версия не определена)";

        using var cancellationRegistration = cancellationToken.Register(() => TryKill(process));
        try
        {
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();

            bool exited = await WaitForExitWithTimeoutAsync(
                process,
                VersionTimeout,
                cancellationToken);
            if (!exited)
                return "sing-box (таймаут определения версии)";

            string output = (await stdoutTask) + Environment.NewLine + (await stderrTask);
            string? versionLine = output
                .Replace("\r", string.Empty, StringComparison.Ordinal)
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(line => line.StartsWith("sing-box version ", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrWhiteSpace(versionLine))
                return "sing-box";

            return versionLine.Length <= 96
                ? versionLine
                : versionLine[..96];
        }
        finally
        {
            // Cancellation must not leave a version/check child behind.
            await StopCheckProcessAsync(process);
        }
    }

    private static async Task<SingBoxCheckResult> RunCheckAsync(
        string executablePath,
        string engineVersion,
        byte[] configurationUtf8,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProcessStartInfo startInfo = CreateBaseStartInfo(executablePath);
        startInfo.RedirectStandardInput = true;
        startInfo.ArgumentList.Add("check");
        startInfo.ArgumentList.Add("--disable-color");
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add("stdin");

        using Process process = new() { StartInfo = startInfo };
        if (!process.Start())
        {
            return SingBoxCheckResult.Rejected(
                engineVersion,
                -1,
                "Не удалось запустить sing-box check.");
        }

        using var cancellationRegistration = cancellationToken.Register(() => TryKill(process));
        try
        {
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();

            try
            {
                await process.StandardInput.BaseStream.WriteAsync(
                    configurationUtf8.AsMemory(),
                    cancellationToken);
                await process.StandardInput.BaseStream.FlushAsync(cancellationToken);
            }
            finally
            {
                process.StandardInput.Close();
            }

            bool exited = await WaitForExitWithTimeoutAsync(
                process,
                CheckTimeout,
                cancellationToken);
            if (!exited)
            {
                return SingBoxCheckResult.Rejected(
                    engineVersion,
                    -2,
                    "Проверка sing-box превысила безопасный таймаут 20 секунд.");
            }

            string stdout = await stdoutTask;
            string stderr = await stderrTask;
            if (process.ExitCode == 0)
            {
                return SingBoxCheckResult.Accepted(
                    engineVersion,
                    "Конфигурация принята sing-box; открытый JSON на диск не записывался.");
            }

            string safeEngineError = SanitizeEngineOutput(stderr + Environment.NewLine + stdout);
            return SingBoxCheckResult.Rejected(
                engineVersion,
                process.ExitCode,
                "sing-box отклонил конфигурацию: " + safeEngineError);
        }
        finally
        {
            // Cancellation must not leave a version/check child behind.
            await StopCheckProcessAsync(process);
        }
    }

    private static ProcessStartInfo CreateBaseStartInfo(string executablePath) =>
        new()
        {
            FileName = executablePath,
            WorkingDirectory = IOPath.GetDirectoryName(executablePath) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

    private static async Task<bool> WaitForExitWithTimeoutAsync(
        Process process,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
            cancellationToken.ThrowIfCancellationRequested();
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            try
            {
                await process.WaitForExitAsync(CancellationToken.None);
            }
            catch
            {
                // Best effort: the caller only needs the timeout result.
            }

            return false;
        }
    }

    private static async Task StopCheckProcessAsync(Process process)
    {
        TryKill(process);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        { throw new System.IO.IOException("Не удалось остановить процесс проверки конфигурации."); }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Best effort cleanup only.
        }
    }

    private static string SanitizeEngineOutput(string rawOutput)
    {
        if (string.IsNullOrWhiteSpace(rawOutput))
            return "движок не вернул безопасного текста ошибки";

        IEnumerable<string> lines = rawOutput
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(6);

        string sanitized = string.Join(" | ", lines);
        sanitized = SensitiveAssignmentRegex().Replace(sanitized, "$1=<hidden>");
        sanitized = UuidRegex().Replace(sanitized, "<uuid>");
        sanitized = Ipv4Regex().Replace(sanitized, "<ip>");
        sanitized = HostNameRegex().Replace(sanitized, "<host>");
        sanitized = LongBase64Regex().Replace(sanitized, "<encoded>");
        sanitized = LongQuotedValueRegex().Replace(sanitized, "\"<hidden>\"");

        sanitized = sanitized.Trim();
        if (sanitized.Length == 0)
            return "движок не вернул безопасного текста ошибки";

        return sanitized.Length <= 700
            ? sanitized
            : sanitized[..700] + "…";
    }

    [GeneratedRegex(
        "(?i)\\b(password|uuid|server|server_name|sni|secret|token|key)\\s*[:=]\\s*(?:\"[^\"]*\"|'[^']*'|\\S+)",
        RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveAssignmentRegex();

    [GeneratedRegex(
        @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex UuidRegex();

    [GeneratedRegex(
        @"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])",
        RegexOptions.CultureInvariant)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(
        @"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
        RegexOptions.CultureInvariant)]
    private static partial Regex HostNameRegex();

    [GeneratedRegex(
        @"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])",
        RegexOptions.CultureInvariant)]
    private static partial Regex LongBase64Regex();

    [GeneratedRegex(
        "\\\"[^\\\"\\r\\n]{24,}\\\"",
        RegexOptions.CultureInvariant)]
    private static partial Regex LongQuotedValueRegex();
}
