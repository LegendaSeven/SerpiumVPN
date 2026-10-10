using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SerpiumVPN.Relay.Routing;

internal sealed record UserNetworkProcess(string Path, bool HasWindow, bool UsesInternet, string ApplicationId = "");

/// <summary>Reads endpoint ownership and window/process identity only; never captures packets.</summary>
internal static class UserNetworkProcessSnapshot
{
    internal static IReadOnlyList<UserNetworkProcess> Capture(CancellationToken token, IReadOnlySet<string>? engineObservedPaths = null)
    {
        HashSet<int> internet = ReadInternetProcessIds();
        var windows = new HashSet<int>();
        EnumWindows((window, _) =>
        {
            if (IsWindowVisible(window) && GetWindowTextLength(window) > 0)
            {
                GetWindowThreadProcessId(window, out int pid);
                if (pid > 0) windows.Add(pid);
            }
            return true;
        }, IntPtr.Zero);
        using WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
        string? currentSid = currentIdentity.User?.Value;
        if (currentSid is null) return [];
        using var currentProcess = Process.GetCurrentProcess();
        int session = currentProcess.SessionId;
        var result = new List<UserNetworkProcess>();
        // UDP tables supply owners, never proof of internet access. The engine supplies
        // that proof separately, and Windows still verifies the user's SID and session.
        var candidates = internet.Union(windows);
        if (engineObservedPaths?.Count > 0) candidates = candidates.Union(ReadUdpProcessIds());
        foreach (int pid in candidates)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if (!ProcessIdToSessionId(pid,out int otherSession) || session != otherSession || otherSession == 0) continue;
                using SafeProcessHandle process = OpenProcess(0x1000, false, pid);
                if (process.IsInvalid || !OpenProcessToken(process, 0x0008, out SafeAccessTokenHandle accessToken)) continue;
                using (accessToken)
                using (var identity = new WindowsIdentity(accessToken.DangerousGetHandle()))
                {
                    if (identity.User?.Value != currentSid) continue;
                }
                var name = new StringBuilder(32768);
                int size = name.Capacity;
                if (QueryFullProcessImageName(process,0,name,ref size))
                    result.Add(new(name.ToString(),windows.Contains(pid),internet.Contains(pid) || engineObservedPaths?.Contains(name.ToString()) == true, ReadApplicationId(process)));
            }
            catch (Exception error) when (error is Win32Exception or InvalidOperationException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException) { }
        }
        return result;
    }

    private static string ReadApplicationId(SafeProcessHandle process)
    {
        uint length = 261;
        var value = new StringBuilder((int)length);
        return GetApplicationUserModelId(process, ref length, value) == 0 && WindowsApplicationCatalog.IsPackageIdentity(value.ToString()) ? value.ToString() : "";
    }

    internal static HashSet<int> ReadInternetProcessIds()
    {
        var result = new HashSet<int>();
        foreach (int family in new[] { 2, 23 })
        {
            int size = 0;
            uint status = GetExtendedTcpTable(IntPtr.Zero,ref size,false,family,5,0);
            for (int attempt = 0; status == 122 && attempt < 3 && size is > 0 and < 16_777_216; attempt++)
            {
                int capacity = size;
                IntPtr buffer = Marshal.AllocHGlobal(capacity);
                try
                {
                    status = GetExtendedTcpTable(buffer,ref size,false,family,5,0);
                    if (status != 0) continue;
                    int rowSize = family == 2 ? 24 : 56;
                    int count = Marshal.ReadInt32(buffer);
                    if (count < 0 || count > (capacity - 4) / rowSize) break;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr row = IntPtr.Add(buffer,4+i*rowSize);
                        int state = Marshal.ReadInt32(row,family == 2 ? 0 : 48);
                        // Include pending connections too: blocked apps still need VPN selection.
                        if (state is < 3 or > 10) continue;
                        byte[] bytes = new byte[family == 2 ? 4 : 16];
                        Marshal.Copy(IntPtr.Add(row,family == 2 ? 12 : 24),bytes,0,bytes.Length);
                        if (!UserApplicationPolicy.IsInternetAddress(new IPAddress(bytes))) continue;
                        int pid = Marshal.ReadInt32(row,family == 2 ? 20 : 52);
                        if (pid > 0) result.Add(pid);
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
        return result;
    }

    private static HashSet<int> ReadUdpProcessIds()
    {
        var result = new HashSet<int>();
        foreach (int family in new[] { 2, 23 })
        {
            int size = 0;
            uint status = GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, 1, 0);
            for (int attempt = 0; status == 122 && attempt < 3 && size is > 0 and < 16_777_216; attempt++)
            {
                int capacity = size;
                IntPtr buffer = Marshal.AllocHGlobal(capacity);
                try
                {
                    status = GetExtendedUdpTable(buffer, ref size, false, family, 1, 0);
                    if (status != 0) continue;
                    int rowSize = family == 2 ? 12 : 28;
                    int count = Marshal.ReadInt32(buffer);
                    if (count < 0 || count > (capacity - 4) / rowSize) break;
                    for (int i = 0; i < count; i++)
                    {
                        int pid = Marshal.ReadInt32(buffer, 4 + i * rowSize + rowSize - 4);
                        if (pid > 0) result.Add(pid);
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }
        return result;
    }

    private delegate bool EnumWindowsCallback(IntPtr window,IntPtr parameter);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsCallback callback,IntPtr parameter);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr window);
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window,out int processId);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(int processId,out int sessionId);
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)] bool inherit,int processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    private static extern int GetApplicationUserModelId(SafeProcessHandle process, ref uint length, StringBuilder value);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,StringBuilder name,ref int size);
    [DllImport("advapi32.dll",SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table,ref int size,[MarshalAs(UnmanagedType.Bool)] bool sorted,int family,int tableClass,uint reserved);
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool sorted, int family, int tableClass, uint reserved);
}
