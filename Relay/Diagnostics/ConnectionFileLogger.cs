using System.IO;
using System.Text;

namespace SerpiumVPN.Relay.Diagnostics;

internal sealed class ConnectionFileLogger(string path)
{
    private readonly object _gate = new();
    private readonly string _path = Path.GetFullPath(path);

    internal void Write(string message)
    {
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                if (File.Exists(_path) && new FileInfo(_path).Length > 2 * 1024 * 1024)
                    File.Move(_path, Path.ChangeExtension(_path, ".previous.log"), overwrite: true);
                File.AppendAllText(_path, $"{DateTimeOffset.Now:O} {SensitiveDiagnosticRedactor.RedactText(message)}{Environment.NewLine}", Encoding.UTF8);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
