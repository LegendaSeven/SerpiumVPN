using System.Diagnostics;
using System.Reflection;

namespace SerpiumVPN;

internal static class AppVersionInfo
{
    public static string Current
    {
        get
        {
            var assembly = Assembly.GetExecutingAssembly();

            var informationalVersion = assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion;

            if (!string.IsNullOrWhiteSpace(informationalVersion))
            {
                return informationalVersion.Split('+')[0];
            }

            var fileVersion = FileVersionInfo
                .GetVersionInfo(assembly.Location)
                .FileVersion;

            if (!string.IsNullOrWhiteSpace(fileVersion))
            {
                return Normalize(fileVersion);
            }

            return assembly
                .GetName()
                .Version?
                .ToString(3)
                ?? "0.0.0";
        }
    }

    public static string Display => $"Версия {Current}";

    private static string Normalize(string version)
    {
        return Version.TryParse(version, out var parsed)
            ? $"{parsed.Major}.{parsed.Minor}.{parsed.Build}"
            : version;
    }
}
