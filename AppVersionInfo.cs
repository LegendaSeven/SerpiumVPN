using System.Reflection;

namespace SerpiumVPN;

internal static class AppVersionInfo
{
    public static string Current
    {
        get
        {
            string? informationalVersion =
                Assembly.GetExecutingAssembly()
                    .GetCustomAttribute<
                        AssemblyInformationalVersionAttribute>()
                    ?.InformationalVersion;

            if (!string.IsNullOrWhiteSpace(informationalVersion))
            {
                int metadataIndex =
                    informationalVersion.IndexOf('+');

                return metadataIndex >= 0
                    ? informationalVersion[..metadataIndex]
                    : informationalVersion;
            }

            return Assembly.GetExecutingAssembly()
                .GetName()
                .Version?
                .ToString()
                ?? "0.0.0.0";
        }
    }

    public static string Display => $"Версия {Current}";
}