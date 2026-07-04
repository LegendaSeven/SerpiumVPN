using System;
using System.IO;
using System.Text.Json;

namespace SerpiumVPN
{
    public sealed class UserRuntimeSettings
    {
        public bool CheckYouTube { get; set; } = true;
        public bool CheckDiscord { get; set; } = true;
        public bool AutoSwitchStrategies { get; set; } = false;
        public bool AutoUpdateFiles { get; set; } = true;
        public bool AutoUpdateProgram { get; set; } = true;
        public bool AutoStartLastStrategy { get; set; } = true;
        public string? LastStrategyName { get; set; }
        public DateTime? LastStrategySavedAt { get; set; }

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
                return JsonSerializer.Deserialize<UserRuntimeSettings>(json) ?? new UserRuntimeSettings();
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
