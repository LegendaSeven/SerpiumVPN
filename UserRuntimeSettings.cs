using System;
using System.IO;
using System.Text.Json;

namespace SerpiumVPN
{
    public sealed class UserRuntimeSettings
    {
        public bool AutoUpdateTelegramProxy { get; set; } = true;
        public bool AutoUpdateProgram { get; set; } = true;
        public bool AutoCheckRelayComponents { get; set; } = true;
        public DateTimeOffset? LastRelayComponentCheckUtc { get; set; }
        public string? LastKnownSingBoxRelease { get; set; }
        public string? LastKnownXrayRelease { get; set; }

        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        public static string SettingsPath =>
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bin_files", "serpium.runtime.json");

        public static UserRuntimeSettings Load()
        {
            try
            {
                if (!File.Exists(SettingsPath))
                    return new UserRuntimeSettings();

                string json = File.ReadAllText(SettingsPath);
                var settings = JsonSerializer.Deserialize<UserRuntimeSettings>(json) ?? new UserRuntimeSettings();
                using var document = JsonDocument.Parse(json);
                // Preserve the component update preference saved by earlier versions.
                if (document.RootElement.ValueKind == JsonValueKind.Object &&
                    !document.RootElement.TryGetProperty(nameof(AutoUpdateTelegramProxy), out _) &&
                    document.RootElement.TryGetProperty("AutoUpdateFiles", out var oldPreference) &&
                    oldPreference.ValueKind is JsonValueKind.True or JsonValueKind.False)
                {
                    settings.AutoUpdateTelegramProxy = oldPreference.GetBoolean();
                }
                return settings;
            }
            catch
            {
                return new UserRuntimeSettings();
            }
        }

        public void Save()
        {
            string? directory = Path.GetDirectoryName(SettingsPath);
            if (!string.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, JsonOptions));
        }
    }
}
