using System.Runtime.InteropServices;

namespace SerpiumVPN;

internal static class AppIdentity
{
    // Shared with the installer shortcuts; independent of executable location and version.
    internal const string UserModelId = "SerpiumVPN.Desktop";

    internal static void Initialize() => SetCurrentProcessExplicitAppUserModelID(UserModelId);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);
}
