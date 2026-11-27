using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SerpiumVPN.Relay.Providers;

namespace SerpiumVPN.Relay.Outline;

public sealed class OutlinePrefixSession : IDisposable
{
    private Process? _process;
    private Task? _errors;
    public bool Required { get; private set; }
    public bool IsRunning => _process is { HasExited: false };

    public async Task<ProviderRuntimeProfile> PrepareAsync(ProviderRuntimeProfile source, string executable, CancellationToken token)
    {
        byte[] bytes = source.CopyConfiguration();
        try
        {
            var root = JsonNode.Parse(bytes)!.AsObject();
            await PrepareAsync(root, executable, token);
            return new(source.ProviderName, source.ProfileId, source.Engine, Encoding.UTF8.GetBytes(root.ToJsonString()),
                source.Protocols, source.InboundCount, source.OutboundCount, source.RouteRuleCount, source.DnsServerCount,
                source.SafeSchemaSummary, source.ClashApiPort, source.ClashApiSecret);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public async Task PrepareAsync(JsonObject root, string executable, CancellationToken token)
    {
        if (_process is not null) throw new InvalidOperationException("Транспорт Outline уже запущен.");
        var outbound = OutlinePrefixConfiguration.FindOutbound(root);
        Required = outbound is not null;
        if (outbound is null) return;
        if (!File.Exists(executable)) throw new FileNotFoundException("Модуль Outline не найден. Установите полную версию Serpium.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8));
        string secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        byte[] config = Encoding.UTF8.GetBytes(OutlinePrefixConfiguration.HelperConfiguration(outbound, secret).ToJsonString() + "\n");
        try
        {
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(executable))!,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            _process = Process.Start(start) ?? throw new IOException("Не удалось запустить Outline.");
            _errors = DrainAsync(_process.StandardError);
            await _process.StandardInput.BaseStream.WriteAsync(config, deadline.Token);
            await _process.StandardInput.BaseStream.FlushAsync(deadline.Token);
            string? ready = await _process.StandardOutput.ReadLineAsync(deadline.Token);
            if (ready is null || ready.Length > 256 || _process.HasExited) throw new IOException("Транспорт Outline не запустился.");
            int port = JsonNode.Parse(ready)!["port"]!.GetValue<int>();
            token.ThrowIfCancellationRequested();
            OutlinePrefixConfiguration.Bind(outbound, port, secret);
            // Keep stdin open: its closure also stops the helper when the application crashes.
        }
        catch { await StopAsync(); throw; }
        finally { CryptographicOperations.ZeroMemory(config); }
    }

    public async Task StopAsync()
    {
        var process = _process; _process = null; Required = false;
        if (process is null) return;
        try
        {
            try { process.StandardInput.Close(); } catch (IOException) { }
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (TimeoutException) { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)); }
            if (_errors is not null) await _errors.WaitAsync(TimeSpan.FromSeconds(2));
        }
        finally { process.Dispose(); _errors = null; }
    }
    private static async Task DrainAsync(StreamReader reader)
    {
        char[] buffer = new char[1024];
        try { while (await reader.ReadAsync(buffer) > 0) Array.Clear(buffer); }
        catch (IOException) { }
        finally { Array.Clear(buffer); }
    }
    public void Dispose()
    {
        var process = _process; _process = null; Required = false;
        if (process is null) return;
        try { process.StandardInput.Close(); if (!process.HasExited) process.Kill(true); }
        catch (InvalidOperationException) { } catch (IOException) { }
        finally { process.Dispose(); }
    }
}
