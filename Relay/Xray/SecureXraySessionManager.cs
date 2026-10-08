using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using SerpiumVPN.Relay;
using SerpiumVPN.Relay.Parser;

namespace SerpiumVPN.Relay.Xray;

/// <summary>
/// Security boundary around the existing Xray session manager.
///
/// The wrapped manager still builds and launches Xray, but it never receives
/// the legacy build-output config path. Configuration travels through stdin;
/// runtime state stays in a private CurrentUser LocalAppData directory. The actual TCP listener owner is verified against either the source binary
/// or the fixed managed LocalAppData xray-key-client.exe copy with an exact SHA-256 match, and
/// legacy plaintext configs are removed before and after startup.
/// </summary>
public sealed class SecureXraySessionManager : IDisposable
{
    private const int AddressFamilyInterNetwork = 2;
    private const uint ErrorInsufficientBuffer = 122;
    private const int TcpTableOwnerPidListener = 3;

    private readonly SerpiumXraySessionManager _inner = new();
    private readonly object _sync = new();

    private int? _verifiedOwnerProcessId;
    private int? _verifiedSocksPort;
    private string? _expectedXrayPath;
    private string? _legacyConfigPath;
    private string? _securityError;
    private bool _disposed;

    private static readonly string PrivateRuntimeDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SerpiumVPN",
        "Runtime",
        "Xray");

    private static readonly string PrivateRuntimeConfigPath = Path.Combine(
        PrivateRuntimeDirectory,
        "key-client.json");

    private const string ManagedRuntimeExecutableFileName =
        "xray-key-client.exe";

    private static readonly string ManagedRuntimeExecutableDirectory =
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
            "SerpiumVPN",
            "Runtime",
            "key-client");

    public SecureXraySessionManager()
    {
        EnsurePrivateRuntimeDirectory();
        DeleteKnownConfigsBestEffort();
    }

    public RelayGatewayState State
    {
        get
        {
            RelayGatewayState innerState = _inner.State;
            if (innerState != RelayGatewayState.Running)
                return innerState;

            return TryVerifyStoredOwner(out _)
                ? RelayGatewayState.Running
                : RelayGatewayState.Failed;
        }
    }

    public string? LastError =>
        _securityError ?? _inner.LastError;

    public int? ProcessId
    {
        get
        {
            lock (_sync)
            {
                return _verifiedOwnerProcessId;
            }
        }
    }

    public bool HasLiveProcess
    {
        get
        {
            if (!_inner.HasLiveProcess)
                return false;

            lock (_sync)
            {
                if (_verifiedOwnerProcessId is null ||
                    _verifiedSocksPort is null ||
                    string.IsNullOrWhiteSpace(_expectedXrayPath))
                {
                    // During the wrapped manager's Starting state, ownership has
                    // not yet been verified.
                    return _inner.State == RelayGatewayState.Starting;
                }
            }

            return TryVerifyStoredOwner(out _);
        }
    }

    public event Action<string>? LogReceived
    {
        add => _inner.LogReceived += value;
        remove => _inner.LogReceived -= value;
    }

    public event Action<RelayGatewayState>? StateChanged
    {
        add => _inner.StateChanged += value;
        remove => _inner.StateChanged -= value;
    }

    public async Task StartAsync(
        string sourceXrayPath,
        string legacyConfigPath,
        SerpiumConnectionProfile profile,
        int socksPort,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(profile);

        if (string.IsNullOrWhiteSpace(sourceXrayPath))
            throw new ArgumentException("Путь Xray пуст.", nameof(sourceXrayPath));

        if (socksPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(socksPort));

        string fullXrayPath = Path.GetFullPath(sourceXrayPath);
        string fullLegacyConfigPath = Path.GetFullPath(legacyConfigPath);

        EnsurePrivateRuntimeDirectory();
        DeleteKnownConfigsStrict(fullLegacyConfigPath);

        lock (_sync)
        {
            _verifiedOwnerProcessId = null;
            _verifiedSocksPort = null;
            _expectedXrayPath = fullXrayPath;
            _legacyConfigPath = fullLegacyConfigPath;
            _securityError = null;
        }

        try
        {
            await ReapStaleOwnedListenerAsync(
                fullXrayPath,
                socksPort,
                cancellationToken).ConfigureAwait(false);

            DeleteKnownConfigsStrict(fullLegacyConfigPath);

            await _inner.StartAsync(
                fullXrayPath,
                PrivateRuntimeConfigPath,
                profile,
                socksPort,
                cancellationToken).ConfigureAwait(false);

            ListenerOwner owner = await WaitForExpectedListenerOwnerAsync(
                fullXrayPath,
                socksPort,
                cancellationToken).ConfigureAwait(false);

            lock (_sync)
            {
                _verifiedOwnerProcessId = owner.ProcessId;
                _verifiedSocksPort = socksPort;
            }

            // Fail closed: a successful connection is not exposed to the UI
            // until all known plaintext copies have actually disappeared.
            DeleteKnownConfigsStrict(fullLegacyConfigPath);

            if (!TryVerifyStoredOwner(out string verificationError))
            {
                throw new InvalidOperationException(
                    "Xray открыл SOCKS-порт, но проверка владельца не удержалась: " +
                    verificationError);
            }
        }
        catch (Exception ex)
        {
            lock (_sync)
            {
                _securityError =
                    "Защищённый запуск Xray не завершён: " + ex.Message;
            }

            try
            {
                if (_inner.HasLiveProcess ||
                    _inner.State != RelayGatewayState.Stopped)
                {
                    await _inner.StopAsync(CancellationToken.None)
                        .ConfigureAwait(false);
                }
            }
            catch
            {
                // Cleanup below is mandatory even if the wrapped manager failed.
            }

            ClearVerifiedOwner();
            DeleteKnownConfigsBestEffort(fullLegacyConfigPath);
            throw;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Exception? stopError = null;
        try
        {
            await _inner.StopAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            stopError = ex;
        }
        finally
        {
            ClearVerifiedOwner();
            DeleteKnownConfigsBestEffort();
        }

        if (stopError is not null)
            throw stopError;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        try
        {
            if (_inner.HasLiveProcess ||
                _inner.State != RelayGatewayState.Stopped)
            {
                _inner.StopAsync(CancellationToken.None)
                    .GetAwaiter()
                    .GetResult();
            }
        }
        catch
        {
            // Final process shutdown remains best effort.
        }

        try
        {
            _inner.Dispose();
        }
        finally
        {
            ClearVerifiedOwner();
            DeleteKnownConfigsBestEffort();
        }
    }

    private static async Task<ListenerOwner> WaitForExpectedListenerOwnerAsync(
        string expectedXrayPath,
        int socksPort,
        CancellationToken cancellationToken)
    {
        string lastError = "порт ещё не найден";

        for (int attempt = 0; attempt < 30; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (TryGetListenerOwner(socksPort, out int ownerProcessId))
            {
                if (TryValidateOwnerProcess(
                        ownerProcessId,
                        expectedXrayPath,
                        out string ownerPath,
                        out string validationError))
                {
                    return new ListenerOwner(ownerProcessId, ownerPath);
                }

                lastError = validationError;
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }

        throw new InvalidOperationException(
            $"SOCKS-порт 127.0.0.1:{socksPort} не принадлежит ожидаемому " +
            $"процессу Xray. Последняя проверка: {lastError}");
    }

    private static async Task ReapStaleOwnedListenerAsync(
        string expectedXrayPath,
        int socksPort,
        CancellationToken cancellationToken)
    {
        if (!TryGetListenerOwner(socksPort, out int ownerProcessId))
            return;

        if (!TryValidateOwnerProcess(
                ownerProcessId,
                expectedXrayPath,
                out string ownerPath,
                out string validationError))
        {
            throw new InvalidOperationException(
                $"SOCKS5-порт {socksPort} уже занят посторонним процессом. " +
                validationError);
        }

        try
        {
            using Process staleProcess =
                Process.GetProcessById(ownerProcessId);

            if (staleProcess.HasExited)
                return;

            staleProcess.Kill(entireProcessTree: true);

            using CancellationTokenSource timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(4));

            try
            {
                await staleProcess.WaitForExitAsync(timeout.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
                when (!cancellationToken.IsCancellationRequested)
            {
                throw new InvalidOperationException(
                    "Старый Xray Serpium не завершился за 4 секунды: " +
                    ownerPath);
            }
        }
        catch (ArgumentException)
        {
            // The process disappeared between the TCP-table query and lookup.
        }

        for (int attempt = 0; attempt < 40; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!TryGetListenerOwner(socksPort, out _))
                return;

            await Task.Delay(100, cancellationToken)
                .ConfigureAwait(false);
        }

        throw new InvalidOperationException(
            $"Старый Xray Serpium завершён, но порт {socksPort} " +
            "не освободился.");
    }

    private static bool IsAllowedXrayProcessName(string processName) =>
        processName.Equals(
            "xray",
            StringComparison.OrdinalIgnoreCase) ||
        processName.Equals(
            "xray-client",
            StringComparison.OrdinalIgnoreCase) ||
        processName.Equals(
            "xray-key-client",
            StringComparison.OrdinalIgnoreCase);

    private bool TryVerifyStoredOwner(out string error)
    {
        int? processId;
        int? port;
        string? expectedPath;

        lock (_sync)
        {
            processId = _verifiedOwnerProcessId;
            port = _verifiedSocksPort;
            expectedPath = _expectedXrayPath;
        }

        if (processId is null || port is null ||
            string.IsNullOrWhiteSpace(expectedPath))
        {
            error = "владелец SOCKS-порта ещё не подтверждён";
            return false;
        }

        if (!TryGetListenerOwner(port.Value, out int currentOwner))
        {
            error = $"порт 127.0.0.1:{port.Value} больше не слушается";
            SetSecurityError(error);
            return false;
        }

        if (currentOwner != processId.Value)
        {
            error =
                $"владелец порта изменился: ожидался PID {processId.Value}, " +
                $"получен PID {currentOwner}";
            SetSecurityError(error);
            return false;
        }

        if (!TryValidateOwnerProcess(
                currentOwner,
                expectedPath,
                out _,
                out string validationError))
        {
            error = validationError;
            SetSecurityError(error);
            return false;
        }

        error = string.Empty;
        return true;
    }

    private void SetSecurityError(string error)
    {
        lock (_sync)
        {
            _securityError = "Проверка Xray runtime: " + error;
        }
    }

    private void ClearVerifiedOwner()
    {
        lock (_sync)
        {
            _verifiedOwnerProcessId = null;
            _verifiedSocksPort = null;
            _expectedXrayPath = null;
            _legacyConfigPath = null;
        }
    }

    private static bool TryValidateOwnerProcess(
        int processId,
        string expectedXrayPath,
        out string ownerPath,
        out string error)
    {
        ownerPath = string.Empty;
        error = string.Empty;

        if (processId <= 0 || processId == Environment.ProcessId)
        {
            error = "SOCKS-порт принадлежит недопустимому процессу";
            return false;
        }

        try
        {
            using Process process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                error = $"процесс-владелец PID {processId} уже завершён";
                return false;
            }

            string processName = process.ProcessName;
            if (!IsAllowedXrayProcessName(processName))
            {
                error =
                    $"порт принадлежит процессу '{processName}', а не " +
                    "разрешённому Xray-бинарнику Serpium";
                return false;
            }

            ownerPath = process.MainModule?.FileName ?? string.Empty;
            if (string.IsNullOrWhiteSpace(ownerPath))
            {
                error = "Windows не вернула путь процесса-владельца Xray";
                return false;
            }

            string fullOwnerPath = Path.GetFullPath(ownerPath);
            string fullExpectedPath = Path.GetFullPath(expectedXrayPath);
            string managedRuntimePath =
                GetManagedRuntimeExecutablePath();

            bool isSourceBinary = PathsEqual(
                fullOwnerPath,
                fullExpectedPath);
            bool isManagedRuntimeCopy = PathsEqual(
                fullOwnerPath,
                managedRuntimePath);

            if (!isSourceBinary && !isManagedRuntimeCopy)
            {
                error =
                    "SOCKS-порт открыл Xray из недоверенного расположения: " +
                    DescribeSafePath(fullOwnerPath);
                return false;
            }

            if (isManagedRuntimeCopy &&
                !FilesHaveSameSha256(
                    fullOwnerPath,
                    fullExpectedPath,
                    out string hashError))
            {
                error =
                    "Управляемая runtime-копия Xray не совпадает с " +
                    "исходным бинарником Serpium: " + hashError;
                return false;
            }

            return true;
        }
        catch (ArgumentException)
        {
            error = $"процесс-владелец PID {processId} не найден";
            return false;
        }
        catch (Exception ex)
        {
            error =
                $"не удалось проверить процесс-владелец PID {processId}: " +
                ex.Message;
            return false;
        }
    }

    private static string GetManagedRuntimeExecutablePath() =>
        Path.Combine(
            ManagedRuntimeExecutableDirectory,
            ManagedRuntimeExecutableFileName);

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.GetFullPath(left)
                .TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
            Path.GetFullPath(right)
                .TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

    private static bool FilesHaveSameSha256(
        string candidatePath,
        string expectedPath,
        out string error)
    {
        error = string.Empty;

        try
        {
            if (!File.Exists(candidatePath))
            {
                error = "runtime-бинарник не найден";
                return false;
            }

            if (!File.Exists(expectedPath))
            {
                error = "исходный Xray-бинарник не найден";
                return false;
            }

            byte[] candidateHash;
            byte[] expectedHash;

            using (FileStream candidate = new(
                candidatePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            {
                candidateHash = SHA256.HashData(candidate);
            }

            using (FileStream expected = new(
                expectedPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            {
                expectedHash = SHA256.HashData(expected);
            }

            try
            {
                return CryptographicOperations.FixedTimeEquals(
                    candidateHash,
                    expectedHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(candidateHash);
                CryptographicOperations.ZeroMemory(expectedHash);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string DescribeSafePath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string localAppData = Path.GetFullPath(
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData));

        if (fullPath.StartsWith(
                localAppData,
                StringComparison.OrdinalIgnoreCase))
        {
            return "%LOCALAPPDATA%\\" +
                fullPath[localAppData.Length..].TrimStart(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);
        }

        string applicationBase = Path.GetFullPath(
            AppContext.BaseDirectory);

        if (fullPath.StartsWith(
                applicationBase,
                StringComparison.OrdinalIgnoreCase))
        {
            return "<SERPIUM_APP>\\" +
                fullPath[applicationBase.Length..].TrimStart(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);
        }

        return Path.GetFileName(fullPath);
    }

    private static bool TryGetListenerOwner(int port, out int processId)
    {
        processId = 0;
        int bufferSize = 0;

        uint result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref bufferSize,
            order: false,
            AddressFamilyInterNetwork,
            TcpTableOwnerPidListener,
            reserved: 0);

        if (result != ErrorInsufficientBuffer || bufferSize <= 0)
            return false;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            result = GetExtendedTcpTable(
                buffer,
                ref bufferSize,
                order: false,
                AddressFamilyInterNetwork,
                TcpTableOwnerPidListener,
                reserved: 0);

            if (result != 0)
                return false;

            int rowCount = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            IntPtr rowPointer = IntPtr.Add(buffer, sizeof(uint));

            for (int index = 0; index < rowCount; index++)
            {
                MibTcpRowOwnerPid row =
                    Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPointer);

                int rowPort = ConvertNetworkPort(row.LocalPort);
                if (rowPort == port)
                {
                    processId = checked((int)row.OwningPid);
                    return processId > 0;
                }

                rowPointer = IntPtr.Add(rowPointer, rowSize);
            }

            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ConvertNetworkPort(uint value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        return (bytes[0] << 8) | bytes[1];
    }

    private static void EnsurePrivateRuntimeDirectory()
    {
        Directory.CreateDirectory(PrivateRuntimeDirectory);

        SecurityIdentifier currentUser =
            WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "Не удалось определить SID текущего пользователя.");

        SecurityIdentifier system =
            new(WellKnownSidType.LocalSystemSid, domainSid: null);
        SecurityIdentifier administrators =
            new(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null);

        DirectorySecurity security = new();
        security.SetAccessRuleProtection(
            isProtected: true,
            preserveInheritance: false);
        security.SetOwner(currentUser);

        InheritanceFlags inheritance =
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit;

        foreach (SecurityIdentifier sid in new[]
        {
            currentUser,
            system,
            administrators
        })
        {
            FileSystemAccessRule rule = new(
                sid,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow);

            security.AddAccessRule(rule);
        }

        DirectoryInfo directory = new(PrivateRuntimeDirectory);
        directory.SetAccessControl(security);
    }

    private void DeleteKnownConfigsStrict(string? additionalPath = null)
    {
        foreach (string path in EnumerateKnownConfigPaths(additionalPath))
            DeleteSensitiveFile(path, throwIfRemaining: true);
    }

    private void DeleteKnownConfigsBestEffort(string? additionalPath = null)
    {
        foreach (string path in EnumerateKnownConfigPaths(additionalPath))
        {
            try
            {
                DeleteSensitiveFile(path, throwIfRemaining: false);
            }
            catch
            {
                // Best effort on shutdown. The next startup retries cleanup.
            }
        }
    }

    private IEnumerable<string> EnumerateKnownConfigPaths(
        string? additionalPath = null)
    {
        HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase)
        {
            PrivateRuntimeConfigPath,
            Path.Combine(
                AppContext.BaseDirectory,
                "bin_files",
                "relay",
                "configs",
                "key-client.json")
        };

        lock (_sync)
        {
            if (!string.IsNullOrWhiteSpace(_legacyConfigPath))
                paths.Add(Path.GetFullPath(_legacyConfigPath));
        }

        if (!string.IsNullOrWhiteSpace(additionalPath))
            paths.Add(Path.GetFullPath(additionalPath));

        return paths;
    }

    private static void DeleteSensitiveFile(
        string path,
        bool throwIfRemaining)
    {
        if (!File.Exists(path))
            return;

        Exception? lastError = null;

        for (int attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                try
                {
                    using FileStream stream = new(
                        path,
                        FileMode.Open,
                        FileAccess.Write,
                        FileShare.None);

                    long remaining = stream.Length;
                    byte[] zeros = new byte[16 * 1024];
                    stream.Position = 0;

                    while (remaining > 0)
                    {
                        int count = (int)Math.Min(zeros.Length, remaining);
                        stream.Write(zeros, 0, count);
                        remaining -= count;
                    }

                    stream.Flush(flushToDisk: true);
                    Array.Clear(zeros, 0, zeros.Length);
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    // Deletion can still succeed even if overwrite was blocked.
                }

                File.Delete(path);
                if (!File.Exists(path))
                    return;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }

            Thread.Sleep(125);
        }

        if (throwIfRemaining && File.Exists(path))
        {
            throw new IOException(
                "Не удалось удалить plaintext-конфигурацию Xray: " +
                path,
                lastError);
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    private sealed record ListenerOwner(
        int ProcessId,
        string ExecutablePath);
}
