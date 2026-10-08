using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using SerpiumVPN.Relay.Diagnostics;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Xray;

public sealed class SerpiumKeyValidationService
{
    public async Task<SerpiumKeyValidationResult> ValidateAsync(string xrayPath,
        SerpiumConnectionProfile profile, int socksPort, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(xrayPath)) throw new FileNotFoundException("xray.exe не найден в bin_files\\relay.", xrayPath);
        byte[] configuration = Encoding.UTF8.GetBytes(SerpiumXrayConfigBuilder.Build(profile, socksPort, ""));
        try
        {
            var (valid, message) = await ValidateConfigAsync(xrayPath, configuration, cancellationToken);
            if (!valid) return new SerpiumKeyValidationResult { ConfigValid = false, ServerReachable = false, Message = message };
            bool reachable = await CanConnectAsync(profile.Server, profile.Port, cancellationToken);
            return new SerpiumKeyValidationResult
            {
                ConfigValid = true, ServerReachable = reachable,
                Message = reachable ? "Конфигурация Xray корректна, сервер принимает TCP-соединение." :
                    "Конфигурация Xray корректна, но сервер не ответил на проверку TCP."
            };
        }
        finally { CryptographicOperations.ZeroMemory(configuration); }
    }

    private static async Task<(bool Success, string Message)> ValidateConfigAsync(string path,
        byte[] configuration, CancellationToken cancellationToken)
    {
        var info = new ProcessStartInfo(path)
        {
            WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(path))!,
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (string arg in new[] { "run", "-test", "-config", "stdin:" }) info.ArgumentList.Add(arg);
        using var process = new Process { StartInfo = info };
        if (!process.Start()) return (false, "Не удалось запустить проверку Xray-конфигурации.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        using var registration = deadline.Token.Register(() => TryKill(process));
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        try
        {
            try
            {
                await process.StandardInput.BaseStream.WriteAsync(configuration, deadline.Token);
                process.StandardInput.Close();
            }
            catch (IOException) { deadline.Token.ThrowIfCancellationRequested(); }
            await process.WaitForExitAsync(deadline.Token);
            cancellationToken.ThrowIfCancellationRequested();
            await Task.WhenAll(output, errors);
            if (process.ExitCode == 0) return (true, "Конфигурация Xray корректна.");
            string message = SensitiveDiagnosticRedactor.RedactText(await errors + " " + await output);
            message = string.Join(" ", message.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
            return (false, string.IsNullOrWhiteSpace(message) ? "Xray отклонил конфигурацию." : message[..Math.Min(500, message.Length)]);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return (false, "Проверка Xray-конфигурации превысила 10 секунд."); }
        finally
        {
            TryKill(process);
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(4)); }
            catch (Exception error) when (error is InvalidOperationException or TimeoutException) { }
            try { await Task.WhenAll(output, errors).WaitAsync(TimeSpan.FromSeconds(2)); }
            catch (Exception error) when (error is IOException or ObjectDisposedException or TimeoutException) { }
        }
    }

    private static void TryKill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static async Task<bool> CanConnectAsync(string host, int port, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(6));
        try { await client.ConnectAsync(host, port, deadline.Token); return client.Connected; }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return false; }
        catch (SocketException) { cancellationToken.ThrowIfCancellationRequested(); return false; }
    }
}
