using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Wardogs.Scanner;

public static class AdvancedCollector
{
    private static readonly string[] ExecutableExtensions = [".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".com"];
    private static readonly string[] SuspiciousWords = ["aimbot", "wallhack", "triggerbot", "spoofer", "injector", "cheat", "radarhack", "esp hack", "bypass"];

    public static void Collect(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        CollectSecurityPosture(modules, evidence, errors);
        HardwareCollector.Collect(modules,evidence,errors,token);
        CollectTamperIndicators(modules, evidence, errors, token);
        ModuleCollector.Collect(modules, evidence, errors, token);
        CollectPersistenceHooks(modules, evidence, errors, token);
        CollectRecentExecutables(modules, evidence, errors, token);
        CollectExecutionHistory(modules, evidence, errors, token);
    }

    private static void CollectTamperIndicators(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        var checkedCount = 0;
        var failures = 0;
        foreach (var (log, eventId, label) in new[] { ("Security", 1102, "журнал безпеки"), ("System", 104, "системний журнал") })
        {
            token.ThrowIfCancellationRequested();
            checkedCount++;
            var result = QueryLatestEvent(log, eventId);
            if (!result.Available) { failures++; continue; }
            if (result.Timestamp is null) continue;
            evidence.Add(Item($"event-clear-{log.ToLowerInvariant()}-{eventId}", "event_log_cleared", "tamper_indicators", result.Timestamp,
                "", "WD-EVENTLOG-CLEARED", "medium", "high",
                $"Windows зафіксувала очищення: {label}. Це може бути адміністративна дія, але зменшує надійність історичної перевірки.",
                new() { ["log"] = log, ["event_id"] = eventId }));
        }
        modules.Add(new ModuleResult("tamper_indicators", failures == 0 ? "success" : "partial", started, Now(), checkedCount,
            failures == 0 ? "" : "Частина журналів подій недоступна."));
        if (failures > 0) errors.Add("tamper_indicators: EventLogUnavailable");
    }

    private static void CollectSecurityPosture(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors)
    {
        var started = Now();
        var checkedCount = 0;
        try
        {
            var secureBoot = ReadDword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            checkedCount++;
            evidence.Add(Item("posture-secure-boot", "security_posture", "security_posture", null, "", "WD-POSTURE-SECUREBOOT",
                "none", secureBoot >= 0 ? "confirmed" : "unknown", $"Secure Boot: {PostureLabel(secureBoot)}. Це стан захисту, а не доказ читерства.",
                new() { ["setting"] = "secure_boot", ["value"] = secureBoot, ["observation"] = "firmware_registry", ["cheating_proof"] = false }));

            var codeIntegrity = QueryCodeIntegrity();
            checkedCount++;
            if (codeIntegrity is int options)
            {
                var testSigning = (options & 0x2) != 0;
                var debugMode = (options & 0x80) != 0;
                var flightSigning = (options & 0x200) != 0;
                var weakened = testSigning || debugMode || flightSigning;
                evidence.Add(Item("posture-code-integrity", "code_integrity", "security_posture", null, "", "WD-CODE-INTEGRITY",
                    weakened ? "medium" : "none", weakened ? "high" : "confirmed",
                    weakened ? "Windows запущено з послабленим режимом перевірки підпису коду. Потрібна ручна перевірка." : "Послаблені режими test/debug/flight signing не виявлено.",
                    new() { ["options"] = options, ["test_signing"] = testSigning, ["debug_mode"] = debugMode, ["flight_signing"] = flightSigning }));
            }
            else
            {
                errors.Add("security_posture: CodeIntegrityUnavailable");
            }
            modules.Add(new ModuleResult("security_posture", codeIntegrity is null ? "partial" : "success", started, Now(), checkedCount,
                codeIntegrity is null ? "Не вдалося прочитати стан Code Integrity." : ""));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            modules.Add(new ModuleResult("security_posture", "partial", started, Now(), checkedCount, "Частина параметрів захисту Windows недоступна."));
            errors.Add("security_posture: " + ex.GetType().Name);
        }
    }

    private static void CollectPersistenceHooks(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        var checkedCount = 0;
        try
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var windows = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", false);
                var appInit = Convert.ToString(windows?.GetValue("AppInit_DLLs"))?.Trim() ?? "";
                checkedCount++;
                if (!string.IsNullOrWhiteSpace(appInit))
                    evidence.Add(Item("appinit-" + view, "persistence_hook", "persistence_hooks", null, Normalize(appInit), "WD-APPINIT-DLL",
                        "medium", "medium", "AppInit_DLLs містить модулі для автоматичного завантаження у процеси. Потрібна ручна перевірка.", new() { ["registry_view"] = view.ToString() }));

                using var ifeo = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", false);
                foreach (var target in (ifeo?.GetSubKeyNames() ?? []).Take(500))
                {
                    token.ThrowIfCancellationRequested();
                    using var key = ifeo!.OpenSubKey(target, false);
                    var debugger = Convert.ToString(key?.GetValue("Debugger"))?.Trim() ?? "";
                    checkedCount++;
                    if (string.IsNullOrWhiteSpace(debugger)) continue;
                    evidence.Add(Item("ifeo-" + StableId(view + target), "persistence_hook", "persistence_hooks", null, Normalize(debugger), "WD-IFEO-DEBUGGER",
                        "medium", "medium", "Для виконуваного файла налаштовано IFEO Debugger. Це може бути інструмент розробника або механізм перехоплення запуску.",
                        new() { ["target"] = target, ["registry_view"] = view.ToString() }));
                }
            }

            var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            foreach (var file in EnumerateBounded(tasksRoot, 2, 800).Take(800))
            {
                token.ThrowIfCancellationRequested();
                checkedCount++;
                if (evidence.Count >= 180 || new FileInfo(file).Length > 2_000_000) continue;
                string content;
                try { content = File.ReadAllText(file); } catch { continue; }
                var command = ExtractXmlValue(content, "Command");
                if (string.IsNullOrWhiteSpace(command) || !IsUserWritablePath(Environment.ExpandEnvironmentVariables(command).Trim('"'))) continue;
                evidence.Add(Item("task-" + StableId(file), "scheduled_task", "persistence_hooks", FileTime(file), Normalize(command), "WD-TASK-USERPATH",
                    "none", "unknown", "Завдання запускає файл із користувацького каталогу. Це звичайно для OneDrive та інших програм; сам шлях не є підозрою на чит.",
                    new() { ["task"] = Normalize(file) }));
            }
            modules.Add(new ModuleResult("persistence_hooks", "success", started, Now(), checkedCount, ""));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            modules.Add(new ModuleResult("persistence_hooks", "partial", started, Now(), checkedCount, "Частина persistence-джерел недоступна."));
            errors.Add("persistence_hooks: " + ex.GetType().Name);
        }
    }

    private static void CollectRecentExecutables(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        var checkedCount = 0;
        var candidates = new List<FileInfo>();
        var roots = new[] {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
        }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots)
        {
            foreach (var path in EnumerateBounded(root, 2, 1600))
            {
                token.ThrowIfCancellationRequested();
                checkedCount++;
                if (!ExecutableExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase)) continue;
                try
                {
                    var info = new FileInfo(path);
                    if (info.LastWriteTimeUtc >= DateTime.UtcNow.AddDays(-30)) candidates.Add(info);
                }
                catch { }
            }
        }
        foreach (var info in candidates.OrderByDescending(item => item.LastWriteTimeUtc).Take(100))
        {
            token.ThrowIfCancellationRequested();
            var inspected = InspectFile(info.FullName);
            var suspiciousName = HasSuspiciousName(info.Name);
            evidence.Add(Item("recent-" + StableId(info.FullName), "recent_executable", "recent_executables", FileTime(info.FullName), Normalize(info.FullName),
                suspiciousName ? "WD-RECENT-NAME-REVIEW" : "WD-RECENT-INVENTORY", suspiciousName ? "medium" : "none", suspiciousName ? "low" : "unknown",
                suspiciousName ? "Назва недавнього виконуваного файла збігається із загальним індикатором інструментів втручання. Назва сама по собі не доводить порушення." : "Недавній виконуваний файл зафіксовано для часової кореляції з блокуванням.",
                new() { ["size"] = info.Length, ["created_at"] = UnixOrNull(info.CreationTimeUtc) }, inspected.Hash, inspected.Publisher, inspected.Signature));
        }
        modules.Add(new ModuleResult("recent_executables", "success", started, Now(), checkedCount, ""));
    }

    private static void CollectExecutionHistory(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        var checkedCount = 0;
        var sources = 0;
        var failures = 0;
        try
        {
            var prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            if (Directory.Exists(prefetch))
            {
                sources++;
                foreach (var path in Directory.EnumerateFiles(prefetch, "*.pf").OrderByDescending(File.GetLastWriteTimeUtc).Take(140))
                {
                    token.ThrowIfCancellationRequested();
                    checkedCount++;
                    var info = new FileInfo(path);
                    AddHistory(evidence, "prefetch-" + StableId(info.Name), "prefetch_metadata", "%SYSTEMROOT%\\Prefetch\\" + info.Name,
                        UnixOrNull(info.LastWriteTimeUtc), "WD-PREFETCH-INVENTORY", info.Name, new() { ["size"] = info.Length });
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            failures++; errors.Add("historical_execution.prefetch: " + ex.GetType().Name);
        }

        try
        {
            using (var pca = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", false))
            {
                if (pca != null)
                {
                    sources++;
                    foreach (var path in pca.GetValueNames().Where(LooksExecutable).TakeLast(100))
                    {
                        token.ThrowIfCancellationRequested();
                        checkedCount++;
                        AddHistory(evidence, "pca-" + StableId(path), "pca_execution", Normalize(path), null, "WD-PCA-EXECUTION", Path.GetFileName(path), new());
                    }
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            failures++; errors.Add("historical_execution.pca: " + ex.GetType().Name);
        }

        try
        {
            using (var bam = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", false))
            {
                if (bam != null)
                {
                    sources++;
                    foreach (var sid in bam.GetSubKeyNames())
                    {
                        using var user = bam.OpenSubKey(sid, false);
                        foreach (var path in (user?.GetValueNames() ?? []).Where(LooksExecutable).TakeLast(80))
                        {
                            token.ThrowIfCancellationRequested();
                            checkedCount++;
                            var timestamp = BamTime(user!.GetValue(path));
                            AddHistory(evidence, "bam-" + StableId(sid + path), "bam_execution", Normalize(path), timestamp, "WD-BAM-EXECUTION", Path.GetFileName(path), new());
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            failures++; errors.Add("historical_execution.bam: " + ex.GetType().Name);
        }

        try
        {
            var journal = QueryUsnJournal();
            checkedCount++;
            if (journal != null)
            {
                sources++;
                evidence.Add(Item("usn-journal-status", "journal_status", "historical_execution", null, "C:", "WD-USN-STATUS", "none", "confirmed",
                    "NTFS USN Change Journal доступний для перевірки цілісності історичних слідів.", journal));
                foreach (var trace in ReadRecentUsnTraces(80))
                {
                    token.ThrowIfCancellationRequested();
                    checkedCount++;
                    var suspicious = HasSuspiciousName(trace.Name);
                    evidence.Add(Item("usn-" + StableId(trace.Usn + trace.Name), "usn_file_trace", "historical_execution", trace.Timestamp,
                        trace.Name, suspicious ? "WD-USN-NAME-REVIEW" : "WD-USN-EXECUTABLE-TRACE", suspicious ? "medium" : "none", suspicious ? "low" : "unknown",
                        suspicious ? "USN Journal містить історичний слід файла із загальним індикатором інструментів втручання. Потрібна ручна перевірка." : "USN Journal містить недавній слід створення, перейменування або видалення виконуваного файла.",
                        new() { ["reason"] = $"0x{trace.Reason:x8}", ["usn"] = trace.Usn }));
                }
            }
            else { failures++; errors.Add("historical_execution.usn: Unavailable"); }
        }
        catch (Exception ex)
        {
            failures++; errors.Add("historical_execution.usn: " + ex.GetType().Name);
        }

        try
        {
            var prefetchEnabled = ReadDword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", "EnablePrefetcher");
            checkedCount++;
            if (prefetchEnabled == 0)
                evidence.Add(Item("prefetch-disabled", "history_tampering", "historical_execution", null, "", "WD-PREFETCH-DISABLED", "medium", "medium",
                    "Windows Prefetch вимкнено. Це може мати легітимну причину, але зменшує якість історичної перевірки.", new() { ["value"] = prefetchEnabled }));
        }
        catch (Exception ex)
        {
            failures++; errors.Add("historical_execution.prefetch_state: " + ex.GetType().Name);
        }

        var status = sources == 4 && failures == 0 ? "success" : "partial";
        modules.Add(new ModuleResult("historical_execution", status, started, Now(), checkedCount,
            status == "success" ? "" : $"Доступно {sources} із 4 історичних джерел Windows."));
    }

    private static void AddHistory(List<Evidence> evidence, string id, string type, string path, double? timestamp, string rule, string name, Dictionary<string, object?> details)
    {
        if (evidence.Count >= 430) return;
        var suspicious = HasSuspiciousName(name);
        evidence.Add(Item(id, type, "historical_execution", timestamp, path, suspicious ? "WD-HISTORY-NAME-REVIEW" : rule,
            suspicious ? "medium" : "none", suspicious ? "low" : "unknown",
            suspicious ? "Назва історичного артефакту збігається із загальним індикатором інструментів втручання. Потрібна ручна перевірка." : "Історичний запис виконання зафіксовано для часової кореляції; сам запис не є доказом порушення.", details));
    }

    private static Evidence Item(string id, string type, string source, double? timestamp, string path, string rule,
        string severity, string confidence, string explanation, Dictionary<string, object?> details,
        string hash = "", string publisher = "", string signature = "metadata_only") =>
        new(id, type, source, timestamp, "UTC", "historical_or_scan_time", Truncate(path, 500), hash, Truncate(publisher, 200), signature, rule,
            severity, confidence, explanation, details);

    private static (string Hash, string Publisher, string Signature) InspectFile(string path)
    {
        string hash = "";
        try
        {
            var info = new FileInfo(path);
            if (info.Length <= 200_000_000)
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            }
        }
        catch { }
        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return (hash, certificate.GetNameInfo(X509NameType.SimpleName, false), "signed");
        }
        catch (CryptographicException) { return (hash, "", "unsigned"); }
    }

    private static IEnumerable<string> EnumerateBounded(string root, int maxDepth, int maxEntries)
    {
        if (!Directory.Exists(root)) yield break;
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));
        var emitted = 0;
        while (queue.Count > 0 && emitted < maxEntries)
        {
            var (folder, depth) = queue.Dequeue();
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder); } catch { continue; }
            foreach (var file in files)
            {
                yield return file;
                if (++emitted >= maxEntries) yield break;
            }
            if (depth >= maxDepth) continue;
            try
            {
                foreach (var child in Directory.EnumerateDirectories(folder).Take(200)) queue.Enqueue((child, depth + 1));
            }
            catch { }
        }
    }

    private static string ExtractXmlValue(string xml, string localName)
    {
        try
        {
            var document = System.Xml.Linq.XDocument.Parse(xml, System.Xml.Linq.LoadOptions.None);
            return document.Descendants().FirstOrDefault(item => item.Name.LocalName == localName)?.Value?.Trim() ?? "";
        }
        catch { return ""; }
    }

    private static Dictionary<string, object?>? QueryUsnJournal()
    {
        var root = Path.GetPathRoot(Environment.SystemDirectory);
        if (string.IsNullOrWhiteSpace(root)) return null;
        using var handle = CreateFile($@"\\.\{root.TrimEnd('\\')}", 0x80000000, 0x1 | 0x2, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid) return null;
        var buffer = new byte[128];
        if (!DeviceIoControl(handle, 0x000900f4, IntPtr.Zero, 0, buffer, buffer.Length, out var returned, IntPtr.Zero) || returned < 56) return null;
        return new() {
            ["journal_id"] = BitConverter.ToUInt64(buffer, 0).ToString("x16"),
            ["first_usn"] = BitConverter.ToInt64(buffer, 8), ["next_usn"] = BitConverter.ToInt64(buffer, 16),
            ["maximum_size"] = BitConverter.ToUInt64(buffer, 40), ["allocation_delta"] = BitConverter.ToUInt64(buffer, 48),
        };
    }

    private static List<UsnTrace> ReadRecentUsnTraces(int limit)
    {
        var result = new List<UsnTrace>();
        var root = Path.GetPathRoot(Environment.SystemDirectory);
        if (string.IsNullOrWhiteSpace(root)) return result;
        using var handle = CreateFile($@"\\.\{root.TrimEnd('\\')}", 0x80000000, 0x1 | 0x2, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid) return result;
        var journalBuffer = new byte[128];
        if (!DeviceIoControl(handle, 0x000900f4, IntPtr.Zero, 0, journalBuffer, journalBuffer.Length, out var journalBytes, IntPtr.Zero) || journalBytes < 56) return result;
        var journalId = BitConverter.ToUInt64(journalBuffer, 0);
        var firstUsn = BitConverter.ToInt64(journalBuffer, 8);
        var nextUsn = BitConverter.ToInt64(journalBuffer, 16);
        var request = new ReadUsnJournalData
        {
            StartUsn = Math.Max(firstUsn, nextUsn - 64L * 1024 * 1024), ReasonMask = 0xffffffff,
            ReturnOnlyOnClose = 0, Timeout = 0, BytesToWaitFor = 0, UsnJournalId = journalId,
        };
        var output = new byte[128 * 1024];
        var scanned = 0;
        while (request.StartUsn < nextUsn && scanned < 20_000 && result.Count < limit)
        {
            if (!DeviceIoControl(handle, 0x000900bb, ref request, Marshal.SizeOf<ReadUsnJournalData>(), output, output.Length, out var returned, IntPtr.Zero) || returned <= 8) break;
            var next = BitConverter.ToInt64(output, 0);
            var offset = 8;
            while (offset + 60 <= returned && scanned++ < 20_000 && result.Count < limit)
            {
                var recordLength = BitConverter.ToInt32(output, offset);
                if (recordLength < 60 || offset + recordLength > returned) break;
                var major = BitConverter.ToUInt16(output, offset + 4);
                if (major == 2)
                {
                    var usn = BitConverter.ToInt64(output, offset + 24);
                    var fileTime = BitConverter.ToInt64(output, offset + 32);
                    var reason = BitConverter.ToUInt32(output, offset + 40);
                    var nameLength = BitConverter.ToUInt16(output, offset + 56);
                    var nameOffset = BitConverter.ToUInt16(output, offset + 58);
                    if (nameLength > 0 && nameOffset + nameLength <= recordLength)
                    {
                        var name = System.Text.Encoding.Unicode.GetString(output, offset + nameOffset, nameLength);
                        var interestingReason = (reason & (0x100u | 0x200u | 0x1000u | 0x2000u)) != 0;
                        if (interestingReason && LooksExecutable(name))
                        {
                            double? timestamp = null;
                            try
                            {
                                var parsed = DateTimeOffset.FromFileTime(fileTime);
                                if (parsed >= DateTimeOffset.UtcNow.AddDays(-30) && parsed <= DateTimeOffset.UtcNow.AddMinutes(5)) timestamp = parsed.ToUnixTimeMilliseconds() / 1000d;
                            }
                            catch { }
                            if (timestamp != null) result.Add(new(name, usn, reason, timestamp));
                        }
                    }
                }
                offset += recordLength;
            }
            if (next <= request.StartUsn) break;
            request.StartUsn = next;
        }
        return result.OrderByDescending(item => item.Timestamp ?? 0).Take(limit).ToList();
    }

    private static EventQueryResult QueryLatestEvent(string log, int eventId)
    {
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wevtutil.exe"),
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add("qe");
            start.ArgumentList.Add(log);
            start.ArgumentList.Add($"/q:*[System[(EventID={eventId})]]");
            start.ArgumentList.Add("/rd:true");
            start.ArgumentList.Add("/c:1");
            start.ArgumentList.Add("/f:xml");
            using var process = Process.Start(start);
            if (process is null) return new(false, null);
            var outputTask = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(5000)) { try { process.Kill(true); } catch { } return new(false, null); }
            var output = outputTask.GetAwaiter().GetResult();
            if (process.ExitCode != 0) return new(false, null);
            if (string.IsNullOrWhiteSpace(output)) return new(true, null);
            var document = System.Xml.Linq.XDocument.Parse(output, System.Xml.Linq.LoadOptions.None);
            var value = document.Descendants().FirstOrDefault(item => item.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
            return DateTimeOffset.TryParse(value, out var timestamp) ? new(true, timestamp.ToUnixTimeMilliseconds() / 1000d) : new(true, null);
        }
        catch { return new(false, null); }
    }

    private static int? QueryCodeIntegrity()
    {
        var info = new CodeIntegrityInformation { Length = Marshal.SizeOf<CodeIntegrityInformation>() };
        return NtQuerySystemInformation(103, ref info, info.Length, out _) == 0 ? info.Options : null;
    }

    private static int ReadDword(RegistryKey root, string path, string name)
    {
        try { using var key = root.OpenSubKey(path, false); return Convert.ToInt32(key?.GetValue(name) ?? -1); }
        catch { return -1; }
    }

    private static string PostureLabel(int value) => value switch { 1 => "увімкнено", 0 => "вимкнено", _ => "стан недоступний" };
    private static bool HasSuspiciousName(string value)
    {
        if (value.Contains("anticheat", StringComparison.OrdinalIgnoreCase) || value.Contains("anti-cheat", StringComparison.OrdinalIgnoreCase) || value.Contains("anti_cheat", StringComparison.OrdinalIgnoreCase)) return false;
        return SuspiciousWords.Any(word => value.Contains(word, StringComparison.OrdinalIgnoreCase));
    }
    private static bool LooksExecutable(string value) => ExecutableExtensions.Contains(Path.GetExtension(value), StringComparer.OrdinalIgnoreCase);
    private static bool IsUserWritablePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var expanded = Environment.ExpandEnvironmentVariables(path).Trim().Trim('"');
        return new[] { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Path.GetTempPath() }
            .Where(value => !string.IsNullOrWhiteSpace(value)).Any(value => expanded.StartsWith(value, StringComparison.OrdinalIgnoreCase));
    }
    private static string Normalize(string value)
    {
        var result = Environment.ExpandEnvironmentVariables(value ?? "");
        foreach (var (folder, marker) in new[] { (Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "%USERPROFILE%"), (Environment.GetFolderPath(Environment.SpecialFolder.Windows), "%SYSTEMROOT%") })
            if (!string.IsNullOrWhiteSpace(folder)) result = result.Replace(folder, marker, StringComparison.OrdinalIgnoreCase);
        return Truncate(result, 500);
    }
    private static double? BamTime(object? value)
    {
        try { return value is byte[] bytes && bytes.Length >= 8 ? DateTimeOffset.FromFileTime(BitConverter.ToInt64(bytes, 0)).ToUnixTimeMilliseconds() / 1000d : null; }
        catch { return null; }
    }
    private static double? SafeStartTime(Process process) { try { return new DateTimeOffset(process.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() / 1000d; } catch { return null; } }
    private static double? FileTime(string path) { try { return UnixOrNull(File.GetLastWriteTimeUtc(path)); } catch { return null; } }
    private static double? UnixOrNull(DateTime value) { var result = new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)).ToUnixTimeMilliseconds() / 1000d; return result >= 946684800 ? result : null; }
    private static string StableId(string value) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..20];
    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length];
    private static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;

    private readonly record struct EventQueryResult(bool Available, double? Timestamp);
    private readonly record struct UsnTrace(string Name, long Usn, uint Reason, double? Timestamp);
    [StructLayout(LayoutKind.Sequential)] private struct ReadUsnJournalData
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalId;
    }

    [StructLayout(LayoutKind.Sequential)] private struct CodeIntegrityInformation { public int Length; public int Options; }
    [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int informationClass, ref CodeIntegrityInformation information, int length, out int returnLength);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DeviceIoControl(SafeFileHandle device, uint controlCode, IntPtr input, int inputSize, byte[] output, int outputSize, out int returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DeviceIoControl(SafeFileHandle device, uint controlCode, ref ReadUsnJournalData input, int inputSize, byte[] output, int outputSize, out int returned, IntPtr overlapped);
}
