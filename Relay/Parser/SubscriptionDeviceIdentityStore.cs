using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SerpiumVPN.Relay.Diagnostics;

namespace SerpiumVPN.Relay.Parser;

/// <summary>One persistent random identifier per HTTPS origin, created only after consent. No hardware identifiers.</summary>
public sealed class SubscriptionDeviceIdentityStore
{
    private static readonly object Gate = new();
    private readonly string _directory;
    public SubscriptionDeviceIdentityStore(string? directory = null) => _directory = directory ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SerpiumVPN", "SubscriptionDevices");

    public string? Read(Uri source) => Access(source, create: false);
    public string Authorize(Uri source) => Access(source, create: true)!;

    private string? Access(Uri source, bool create)
    {
        try
        {
            Uri uri = PublicSubscriptionTransport.ValidateUri(source.AbsoluteUri);
            byte[] entropy = SHA256.HashData(Encoding.UTF8.GetBytes("Serpium.SubscriptionDevice.v1|" + uri.GetLeftPart(UriPartial.Authority)));
            string path = Path.Combine(_directory, Convert.ToHexString(entropy) + ".sdevice");
            lock (Gate)
            {
                if (!Directory.Exists(_directory) && !create) return null;
                Directory.CreateDirectory(_directory);
                RejectLink(_directory);
                if (File.Exists(path)) return ReadFile(path, entropy);
                if (!create) return null;
                using var owner = WindowsIdentity.GetCurrent();
                var security = new DirectorySecurity();
                security.SetAccessRuleProtection(true, false);
                foreach (var sid in new[] { owner.User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
                    security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(_directory).SetAccessControl(security);
                byte[] plain = RandomNumberGenerator.GetBytes(32);
                string temp = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    byte[] encrypted = ProtectedData.Protect(plain, entropy, DataProtectionScope.CurrentUser);
                    using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    { file.Write(encrypted); file.Flush(true); }
                    try { File.Move(temp, path, overwrite: false); }
                    catch (IOException) when (File.Exists(path)) { /* Another instance created the same origin first. */ }
                    return ReadFile(path, entropy);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                    if (File.Exists(temp)) File.Delete(temp);
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException or System.Security.SecurityException)
        { throw new ConnectionCheckException(ConnectionFailureKind.SubscriptionDeviceStorage); }
    }

    private static string ReadFile(string path, byte[] entropy)
    {
        RejectLink(path);
        if (new FileInfo(path).Length is < 1 or > 16384) throw new CryptographicException();
        byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(path), entropy, DataProtectionScope.CurrentUser);
        try
        {
            if (plain.Length != 32) throw new CryptographicException();
            return Convert.ToHexString(plain);
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    private static void RejectLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException();
    }
}
