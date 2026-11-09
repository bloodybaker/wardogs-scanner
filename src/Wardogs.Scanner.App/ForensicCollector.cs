using Microsoft.Win32;
using System.IO;

namespace Wardogs.Scanner;

public static class ForensicCollector
{
    public static Task<(List<ModuleResult> Modules, List<Evidence> Evidence, List<string> Errors)> CollectAsync(CancellationToken token)
    {
        return Task.Run(() => Collect(token), token);
    }

    private static (List<ModuleResult>, List<Evidence>, List<string>) Collect(CancellationToken token)
    {
        var modules = new List<ModuleResult>();
        var evidence = new List<Evidence>();
        var errors = new List<string>();
        CollectServices(modules, evidence, errors, token);
        CollectPersistence(modules, evidence, errors, token);
        AdvancedCollector.Collect(modules, evidence, errors, token);
        var now = Now();
        modules.Add(new ModuleResult("cleanup", "success", now, now, 0, ""));
        return (modules, evidence, errors);
    }

    private static void CollectServices(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        var checkedCount = 0;
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            foreach (var name in services?.GetSubKeyNames() ?? [])
            {
                token.ThrowIfCancellationRequested();
                using var service = services!.OpenSubKey(name, false);
                checkedCount++;
                var command = Convert.ToString(service?.GetValue("ImagePath"))?.Trim() ?? "";
                if (string.IsNullOrWhiteSpace(command) || !IsUserWritableCommand(command) || evidence.Count >= 230) continue;
                evidence.Add(Item($"service-{StableId(name)}", "user_writable_service", "services_drivers", null,
                    Normalize(command), "WD-SERVICE-USERPATH", "none", "unknown",
                    "Служба або драйвер має користувацький шлях. Це інвентаризація: сам каталог не доводить підозрілу поведінку чи використання чита.",
                    new() { ["service"] = name, ["start"] = SafeInt(service?.GetValue("Start")), ["type"] = SafeInt(service?.GetValue("Type")) }));
            }
            modules.Add(new ModuleResult("services_drivers", "success", started, Now(), checkedCount, ""));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            modules.Add(new ModuleResult("services_drivers", "partial", started, Now(), checkedCount, "Доступ до частини реєстру обмежено."));
            errors.Add("services_drivers: " + ex.GetType().Name);
        }
    }

    private static void CollectPersistence(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        var checkedCount = 0;
        try
        {
            var keys = new (RegistryKey Root, string Path, string Label)[] {
                (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run 32-bit"),
            };
            foreach (var item in keys)
            {
                token.ThrowIfCancellationRequested();
                using var key = item.Root.OpenSubKey(item.Path, false);
                foreach (var valueName in key?.GetValueNames() ?? [])
                {
                    checkedCount++;
                    if (evidence.Count >= 300) continue;
                    var command = Convert.ToString(key!.GetValue(valueName)) ?? "";
                    evidence.Add(Item($"autorun-{StableId(item.Label + valueName)}", "autorun", "persistence", null,
                        Normalize(command), "WD-AUTORUN-INVENTORY", "none", "unknown",
                        "Запис автозапуску зафіксовано для ручної кореляції; його наявність не є доказом порушення.",
                        new() { ["location"] = item.Label, ["name"] = valueName }));
                }
            }
            foreach (var folder in new[] { Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup })
            {
                var path = Environment.GetFolderPath(folder);
                if (!Directory.Exists(path)) continue;
                foreach (var file in Directory.EnumerateFiles(path).Take(50))
                {
                    token.ThrowIfCancellationRequested();
                    checkedCount++;
                    if (evidence.Count >= 330) continue;
                    var info = new FileInfo(file);
                    evidence.Add(Item($"startup-{StableId(file)}", "startup_item", "persistence", UnixOrNull(info.LastWriteTimeUtc), Normalize(file),
                        "WD-STARTUP-INVENTORY", "none", "unknown", "Елемент папки автозапуску зафіксовано для ручної кореляції.", new() { ["size"] = info.Length }));
                }
            }
            modules.Add(new ModuleResult("persistence", "success", started, Now(), checkedCount, ""));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            modules.Add(new ModuleResult("persistence", "partial", started, Now(), checkedCount, "Доступ до частини джерел обмежено."));
            errors.Add("persistence: " + ex.GetType().Name);
        }
    }

    private static Evidence Item(string id, string type, string source, double? timestamp, string path, string rule,
        string severity, string confidence, string explanation, Dictionary<string, object?> details) =>
        new(id, type, source, timestamp, "UTC", "historical_or_scan_time", Truncate(path, 500), "", "", "metadata_only", rule,
            severity, confidence, explanation, details);

    private static bool IsUserWritableCommand(string command)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command).Trim().Trim('"');
        return new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Path.GetTempPath() }
            .Where(value => !string.IsNullOrWhiteSpace(value)).Any(value => expanded.StartsWith(value, StringComparison.OrdinalIgnoreCase));
    }

    private static string Normalize(string value)
    {
        var result = Environment.ExpandEnvironmentVariables(value ?? "");
        foreach (var (folder, marker) in new[] {
            (Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "%USERPROFILE%"),
            (Environment.GetFolderPath(Environment.SpecialFolder.Windows), "%SYSTEMROOT%") })
            if (!string.IsNullOrWhiteSpace(folder)) result = result.Replace(folder, marker, StringComparison.OrdinalIgnoreCase);
        return Truncate(result, 500);
    }

    private static string StableId(string value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..20];
    private static int SafeInt(object? value) { try { return Convert.ToInt32(value); } catch { return -1; } }
    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length];
    private static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;
    private static double? UnixOrNull(DateTime value)
    {
        var result = new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)).ToUnixTimeMilliseconds() / 1000d;
        return result >= 946684800 ? result : null;
    }
}
