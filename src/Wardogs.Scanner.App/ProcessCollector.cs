using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
namespace Wardogs.Scanner;

public static class ProcessCollector
{
    public static Task<(ModuleResult Module, List<Evidence> Evidence)> CollectAsync(CancellationToken token) =>
        Task.Run(() => CollectCoreAsync(token), token);

    private static async Task<(ModuleResult Module, List<Evidence> Evidence)> CollectCoreAsync(CancellationToken token)
    {
        var started = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;
        var evidence = new List<Evidence>();
        var checkedCount = 0;
        foreach (var process in Process.GetProcesses().OrderBy(item => item.Id))
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if (process.Id == Environment.ProcessId) continue;
                if (GameProcessGuard.IsGameProcess(process.ProcessName)) continue;
                var path = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) continue;
                path = Path.GetFullPath(path);
                checkedCount++;
                var normalized = NormalizePath(path);
                if (!IsReviewLocation(path) || evidence.Count >= 180) continue;
                var hash = await HashAsync(path, token);
                var (publisher, signature) = ReadSignature(path);
                evidence.Add(new Evidence($"process-{process.Id}", "running_process", "processes", SafeStartTime(process), "UTC", "scan_time", normalized, hash, publisher, signature, "WD-PROCESS-INVENTORY", "none", "unknown", "Активний процес зафіксовано для ручної кореляції; сама наявність не є доказом чита.", new() { ["pid"] = process.Id, ["name"] = process.ProcessName }));
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException) { }
            finally { process.Dispose(); }
        }
        var ended = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;
        return (new ModuleResult("processes", "success", started, ended, checkedCount, ""), evidence);
    }
    public static async Task<string> HashAsync(string path, CancellationToken token)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, true);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, token).ConfigureAwait(false)).ToLowerInvariant();
    }
    private static double? SafeStartTime(Process process) { try { return new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000d; } catch { return null; } }
    public static (string Publisher, string Signature) ReadSignature(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return (certificate.GetNameInfo(X509NameType.SimpleName, false), SignatureVerifier.Verify(path));
        }
        catch (CryptographicException) { return ("", "unsigned"); }
    }
    public static string NormalizePath(string path)
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return path.StartsWith(profile, StringComparison.OrdinalIgnoreCase) ? "%USERPROFILE%" + path[profile.Length..] : path;
    }
    private static bool IsReviewLocation(string path)
    {
        var candidates = new[] {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads\\",
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\Temp\\",
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\",
        };
        return candidates.Any(folder => path.StartsWith(folder, StringComparison.OrdinalIgnoreCase));
    }
}
