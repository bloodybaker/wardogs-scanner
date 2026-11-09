using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Wardogs.Scanner;

public static class HardwareCollector
{
    // Read-only CIM queries. Registry configuration is deliberately not treated as runtime state.
    private const string Script = """
        $ErrorActionPreference='Stop'
        $result=@{guard=$null;devices=@();guard_error='';device_error='';device_source='cim'}
        try {$g=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -OperationTimeoutSec 10; $result.guard=@{vbs=$g.VirtualizationBasedSecurityStatus;running=@($g.SecurityServicesRunning);configured=@($g.SecurityServicesConfigured);available=@($g.AvailableSecurityProperties);required=@($g.RequiredSecurityProperties)}} catch {$result.guard_error=$_.Exception.GetType().Name}
        try {$result.devices=@(Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'" -OperationTimeoutSec 10 | Select-Object -First 256 -Property Name,PNPDeviceID,Service,Status,ConfigManagerErrorCode)} catch {
            $result.device_error=$_.Exception.GetType().Name
            $result.device_source='registry_history'
            try {
                $result.devices=@(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -ErrorAction Stop | ForEach-Object {
                    $deviceKey=$_
                    Get-ChildItem -LiteralPath $deviceKey.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $p=Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                        if ($p) { @{Name=($(if($p.FriendlyName){$p.FriendlyName}else{$p.DeviceDesc}));PNPDeviceID=$deviceKey.PSChildName;Service=$p.Service} }
                    }
                } | Select-Object -First 256)
            } catch { $result.device_error += ';RegistryUnavailable' }
        }
        $result | ConvertTo-Json -Depth 5 -Compress
        """;

    public static void Collect(List<ModuleResult> modules, List<Evidence> evidence, List<string> errors, CancellationToken token)
    {
        var started = Now();
        try
        {
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(Script)) }) start.ArgumentList.Add(arg);
            using var process = Process.Start(start) ?? throw new IOException("CIM process unavailable");
            var output = process.StandardOutput.ReadToEndAsync(token);
            var error = process.StandardError.ReadToEndAsync(token);
            var deadline = Stopwatch.StartNew();
            while (!process.WaitForExit(100))
            {
                if (token.IsCancellationRequested || deadline.Elapsed.TotalSeconds > 35)
                { process.Kill(true); token.ThrowIfCancellationRequested(); throw new TimeoutException(); }
            }
            if (process.ExitCode != 0) throw new IOException("CIM query failed");
            var json = output.GetAwaiter().GetResult();
            if (json.Length > 1_000_000) throw new IOException("CIM output exceeded limit");
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            evidence.AddRange(Analyze(root));
            foreach (var (name, field) in new[] { ("runtime_security", "guard_error"), ("dma_devices", "device_error") })
            {
                var failure = root.GetProperty(field).GetString() ?? "";
                modules.Add(new(name, failure.Length == 0 ? "success" : "partial", started, Now(),
                    name == "dma_devices" ? root.GetProperty("devices").GetArrayLength() : 3,
                    failure.Length == 0 ? "" : "Windows CIM не надала частину даних; це не означає вимкнений захист."));
                if (failure.Length > 0) errors.Add(name + ": " + failure);
            }
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or JsonException or System.ComponentModel.Win32Exception)
        {
            foreach (var name in new[] { "runtime_security", "dma_devices" })
                modules.Add(new(name,"partial",started,Now(),0,"Запит стану Windows недоступний або перевищив час очікування."));
            errors.Add("runtime_security: " + ex.GetType().Name);
        }
    }

    public static List<Evidence> Analyze(JsonElement root)
    {
        var result = new List<Evidence>();
        var guard = root.GetProperty("guard");
        if (guard.ValueKind == JsonValueKind.Object)
        {
            var vbs = guard.GetProperty("vbs").ValueKind == JsonValueKind.Number ? guard.GetProperty("vbs").GetInt32() : -1;
            var running = Numbers(guard,"running");
            var runtimeKnown = guard.TryGetProperty("running",out var runtime) && runtime.ValueKind == JsonValueKind.Array && runtime.EnumerateArray().Any(x=>x.ValueKind==JsonValueKind.Number);
            var configured = Numbers(guard,"configured");
            var available = Numbers(guard,"available");
            result.Add(Item("runtime-vbs","security_posture","runtime_security","WD-RUNTIME-VBS","none",
                "VBS: " + (vbs == 2 ? "працює" : vbs == 1 ? "налаштовано, але не працює" : vbs == 0 ? "не ввімкнено" : "стан недоступний") + ". Джерело: Win32_DeviceGuard.",
                new() { ["runtime_state"] = vbs, ["observation"] = "runtime", ["cheating_proof"] = false }));
            result.Add(Item("runtime-hvci","security_posture","runtime_security","WD-RUNTIME-HVCI","none",
                "Memory Integrity (HVCI): " + (!runtimeKnown ? "стан недоступний" : running.Contains(2) ? "працює" : configured.Contains(2) ? "налаштовано, але не працює" : "не працює") + ". Сам по собі стан захисту не доводить читерство.",
                new() { ["running"] = runtimeKnown ? running.Contains(2) : null, ["configured"] = configured.Contains(2), ["observation"] = "runtime" }));
            result.Add(Item("runtime-dma","security_posture","runtime_security","WD-DMA-CAPABILITY","none",
                available.Contains(3) ? "Windows повідомляє про доступність DMA protection. Це не підтвердження активного захисту всіх PCIe-пристроїв і не результат детекції DMA-чита."
                : "Windows не повідомила про доступність DMA protection. Стан Kernel DMA Protection потребує окремої перевірки; DMA-чит цим не встановлено.",
                new() { ["dma_protection_available"] = available.Contains(3), ["kernel_dma_protection"] = "not_measured", ["detection_scope"] = "post_scan_user_mode" }));
        }
        var devices = root.GetProperty("devices");
        var historical = Text(root,"device_source") == "registry_history";
        int n = 0;
        foreach (var device in devices.EnumerateArray())
        {
            var id = Text(device,"PNPDeviceID");
            var name = Text(device,"Name");
            var service = Text(device,"Service");
            var pci = Regex.Match(id,@"VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})",RegexOptions.IgnoreCase);
            var knownDefault = pci.Success && pci.Groups[1].Value.Equals("10EE",StringComparison.OrdinalIgnoreCase) && pci.Groups[2].Value == "0666";
            var researchName = Regex.IsMatch(name+" "+service,@"\b(pcileech|pciescreamer|leechcore)\b",RegexOptions.IgnoreCase);
            if (!knownDefault && !researchName) continue;
            result.Add(Item("dma-device-" + n++,"dma_device_candidate","dma_devices","WD-DMA-PCILEECH-CANDIDATE","medium",
                (historical ? "Запис реєстру про пристрій (наявність зараз не встановлено). " : "") + "PCIe-пристрій має ідентифікатор або назву, що збігається з публічним DMA-дослідницьким обладнанням. Можливе законне використання; ID можна змінити. Це привід перевірити обладнання, а не доказ DMA-чита.",
                new() { ["device_name"] = name[..Math.Min(name.Length,180)], ["pci_vendor"] = pci.Success ? pci.Groups[1].Value : "",
                    ["pci_device"] = pci.Success ? pci.Groups[2].Value : "", ["service"] = service[..Math.Min(service.Length,100)], ["default_id_match"] = knownDefault, ["device_source"] = historical ? "registry_history" : "cim",
                    ["source_reference"] = "github.com/ufrisk/pcileech-fpga/blob/master/ac701_ft601/readme.md", ["cheating_proof"] = false }));
        }
        result.Add(Item("dma-coverage","dma_scan_coverage","dma_devices","WD-DMA-COVERAGE","none",
            (historical ? "CIM недоступна; перевірено лише збережені записи PCIe у реєстрі. " : "") + "Перевірено видимі Windows PCIe-пристрої. Масковане, від’єднане обладнання, прошивка та доступ до пам’яті під час гри цим разовим сканом не перевіряються.",
            new() { ["device_source"] = historical ? "registry_history" : "cim", ["devices_checked"] = devices.GetArrayLength(), ["candidates"] = n, ["dma_cheat_verdict"] = "not_determined" }));
        return result;
    }

    private static HashSet<int> Numbers(JsonElement value,string key) => value.TryGetProperty(key,out var list) && list.ValueKind==JsonValueKind.Array ? list.EnumerateArray().Where(x=>x.ValueKind==JsonValueKind.Number).Select(x=>x.GetInt32()).ToHashSet() : [];
    private static string Text(JsonElement value,string key) => value.TryGetProperty(key,out var item) && item.ValueKind==JsonValueKind.String ? item.GetString() ?? "" : "";
    private static Evidence Item(string id,string type,string source,string rule,string severity,string explanation,Dictionary<string,object?> details) =>
        new(id,type,source,null,"UTC","scan_time","","","","windows_cim",rule,severity,severity=="none"?"confirmed":"medium",explanation,details);
    private static double Now()=>DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()/1000d;
}
