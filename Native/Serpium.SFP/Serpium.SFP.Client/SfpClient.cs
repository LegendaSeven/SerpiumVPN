using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;

namespace Serpium.Sfp;

public enum SfpRoute : uint
{
    Direct = 1,
    Vpn = 2
}

public enum SfpApiResult : uint
{
    Ok = 0,
    Invalid = 1,
    Protocol = 2,
    KernelOffline = 3,
    KernelRejected = 4,
    NotFound = 5,
    Io = 6,
    Internal = 7,
    TooLarge = 8,
    PolicyNotPersisted = 9,
    CutoverIncomplete = 10,
    PersistenceAndCutoverFailed = 11,
    AbortIncomplete = 12
}

public sealed record SfpStatus(
    uint ApiVersion,
    uint KernelProtocolVersion,
    ulong PolicyGeneration,
    SfpRoute DefaultRoute,
    uint PolicyCount,
    uint ActiveFlowCount,
    bool BridgeArmed,
    ulong BridgeProcessId,
    ulong TotalRedirected,
    ulong TotalRedirectFailOpen);

public sealed class SfpApiException : Exception
{
    public uint ApiResult { get; }
    public uint Win32Error { get; }
    public SfpApiResult Result => (SfpApiResult)ApiResult;
    public bool PolicyApplied => Result is SfpApiResult.PolicyNotPersisted
        or SfpApiResult.CutoverIncomplete or SfpApiResult.PersistenceAndCutoverFailed;
    public bool PersistenceFailed => Result is SfpApiResult.PolicyNotPersisted
        or SfpApiResult.PersistenceAndCutoverFailed;
    public bool CutoverIncomplete => Result is SfpApiResult.CutoverIncomplete
        or SfpApiResult.PersistenceAndCutoverFailed or SfpApiResult.AbortIncomplete;

    public SfpApiException(uint apiResult, uint win32Error)
        : base(Describe((SfpApiResult)apiResult) + $" (result={apiResult}, win32={win32Error})")
    {
        ApiResult = apiResult;
        Win32Error = win32Error;
    }

    private static string Describe(SfpApiResult result) => result switch
    {
        SfpApiResult.PolicyNotPersisted => "SFP policy applied, but not saved",
        SfpApiResult.CutoverIncomplete => "SFP policy applied and saved, but flow cutover is incomplete",
        SfpApiResult.PersistenceAndCutoverFailed => "SFP policy applied, but not saved; flow cutover is incomplete",
        SfpApiResult.AbortIncomplete => "SFP flow abort is incomplete; no policy change requested",
        _ => "SFP API failed"
    };
}

public sealed class SfpClient
{
    private const string PipeName = "Serpium.SFP.v1";
    private const uint Magic = 0x41504653;
    private const uint ApiVersion = 0x00010000;
    private const uint HardCutover = 0x00000001;

    private const uint CmdGetStatus = 2;
    private const uint CmdSetDefault = 3;
    private const uint CmdSetAppRoute = 4;
    private const uint CmdRemoveApp = 5;
    private const uint CmdReset = 6;
    private const uint CmdAbortApp = 9;

    private long _requestId;

    public async Task<SfpStatus> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        byte[] payload = await SendAsync(
            CmdGetStatus,
            0,
            ReadOnlyMemory<byte>.Empty,
            cancellationToken);

        if (payload.Length != 56)
            throw new InvalidDataException("Unexpected SFP status size.");

        ReadOnlySpan<byte> span = payload;

        return new SfpStatus(
            BinaryPrimitives.ReadUInt32LittleEndian(span[0..4]),
            BinaryPrimitives.ReadUInt32LittleEndian(span[4..8]),
            BinaryPrimitives.ReadUInt64LittleEndian(span[8..16]),
            (SfpRoute)BinaryPrimitives.ReadUInt32LittleEndian(span[16..20]),
            BinaryPrimitives.ReadUInt32LittleEndian(span[20..24]),
            BinaryPrimitives.ReadUInt32LittleEndian(span[24..28]),
            BinaryPrimitives.ReadUInt32LittleEndian(span[28..32]) != 0,
            BinaryPrimitives.ReadUInt64LittleEndian(span[32..40]),
            BinaryPrimitives.ReadUInt64LittleEndian(span[40..48]),
            BinaryPrimitives.ReadUInt64LittleEndian(span[48..56]));
    }

    public Task SetDefaultRouteAsync(
        SfpRoute route,
        bool hardCutover = true,
        CancellationToken cancellationToken = default)
    {
        byte[] payload = new byte[8];

        BinaryPrimitives.WriteUInt32LittleEndian(
            payload.AsSpan(0, 4),
            (uint)route);

        return SendNoPayloadAsync(
            CmdSetDefault,
            hardCutover ? HardCutover : 0,
            payload,
            cancellationToken);
    }

    public Task SetAppRouteAsync(
        string executablePath,
        SfpRoute route,
        bool hardCutover = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        byte[] path =
            Encoding.Unicode.GetBytes(executablePath);

        byte[] payload =
            new byte[8 + path.Length];

        BinaryPrimitives.WriteUInt32LittleEndian(
            payload.AsSpan(0, 4),
            (uint)route);

        BinaryPrimitives.WriteUInt32LittleEndian(
            payload.AsSpan(4, 4),
            (uint)executablePath.Length);

        path.CopyTo(payload, 8);

        return SendNoPayloadAsync(
            CmdSetAppRoute,
            hardCutover ? HardCutover : 0,
            payload,
            cancellationToken);
    }

    public Task RemoveAppRouteAsync(
        string executablePath,
        bool hardCutover = true,
        CancellationToken cancellationToken = default)
    {
        return SendNoPayloadAsync(
            CmdRemoveApp,
            hardCutover ? HardCutover : 0,
            BuildPathPayload(executablePath),
            cancellationToken);
    }

    public Task ResetPolicyAsync(
        bool hardCutover = true,
        CancellationToken cancellationToken = default)
    {
        return SendNoPayloadAsync(
            CmdReset,
            hardCutover ? HardCutover : 0,
            ReadOnlyMemory<byte>.Empty,
            cancellationToken);
    }

    public async Task AbortAppFlowsAsync(
        string executablePath,
        CancellationToken cancellationToken = default)
    {
        byte[] payload = await SendAsync(
            CmdAbortApp,
            0,
            BuildPathPayload(executablePath),
            cancellationToken);

        if (payload.Length != 16)
            throw new InvalidDataException("Unexpected SFP abort response size.");
        uint matched = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(0, 4));
        uint aborted = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(4, 4));
        uint failed = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(8, 4));
        // Also detect partial failure from an older v1 host returning result=0.
        if (failed != 0 || aborted != matched || matched >= 2048)
            throw new SfpApiException((uint)SfpApiResult.AbortIncomplete, matched >= 2048 ? 234u : 299u);
    }

    private static byte[] BuildPathPayload(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        byte[] path =
            Encoding.Unicode.GetBytes(executablePath);

        byte[] payload =
            new byte[8 + path.Length];

        BinaryPrimitives.WriteUInt32LittleEndian(
            payload.AsSpan(0, 4),
            (uint)executablePath.Length);

        path.CopyTo(payload, 8);

        return payload;
    }

    private async Task SendNoPayloadAsync(
        uint command,
        uint flags,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        _ = await SendAsync(
            command,
            flags,
            payload,
            cancellationToken);
    }

    private async Task<byte[]> SendAsync(
        uint command,
        uint flags,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        using var pipe =
            new NamedPipeClientStream(
                ".",
                PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

        await pipe.ConnectAsync(
            3000,
            cancellationToken);

        ulong requestId =
            unchecked((ulong)Interlocked.Increment(ref _requestId));

        byte[] header = new byte[32];

        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(0, 4), Magic);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4, 4), ApiVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8, 4), command);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12, 4), flags);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(16, 8), requestId);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(24, 4), (uint)payload.Length);

        await pipe.WriteAsync(
            header,
            cancellationToken);

        if (!payload.IsEmpty)
        {
            await pipe.WriteAsync(
                payload,
                cancellationToken);
        }

        await pipe.FlushAsync(
            cancellationToken);

        byte[] responseHeader = new byte[32];

        await ReadExactlyAsync(
            pipe,
            responseHeader,
            cancellationToken);

        ReadOnlySpan<byte> response = responseHeader;

        uint responseMagic =
            BinaryPrimitives.ReadUInt32LittleEndian(response[0..4]);

        uint responseVersion =
            BinaryPrimitives.ReadUInt32LittleEndian(response[4..8]);

        uint result =
            BinaryPrimitives.ReadUInt32LittleEndian(response[12..16]);

        ulong responseRequestId =
            BinaryPrimitives.ReadUInt64LittleEndian(response[16..24]);

        uint responseBytes =
            BinaryPrimitives.ReadUInt32LittleEndian(response[24..28]);

        uint win32Error =
            BinaryPrimitives.ReadUInt32LittleEndian(response[28..32]);

        if (responseMagic != Magic ||
            responseVersion != ApiVersion ||
            responseRequestId != requestId)
        {
            throw new InvalidDataException("SFP API protocol mismatch.");
        }

        if (result != 0)
            throw new SfpApiException(result, win32Error);

        byte[] resultPayload =
            new byte[responseBytes];

        if (responseBytes > 0)
        {
            await ReadExactlyAsync(
                pipe,
                resultPayload,
                cancellationToken);
        }

        return resultPayload;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < buffer.Length)
        {
            int read =
                await stream.ReadAsync(
                    buffer[offset..],
                    cancellationToken);

            if (read == 0)
                throw new EndOfStreamException();

            offset += read;
        }
    }
}
