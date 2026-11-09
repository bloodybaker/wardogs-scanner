using Wardogs.Scanner;
if (args.Length==2 && args[0]=="--handle-owner") { NativeFixture.Hold(int.Parse(args[1])); return; }
if (args.Contains("--guard-child")) { Thread.Sleep(60000); return; }
if (args.Contains("--context-native")) { await ProcessContextFixtures.Native(); return; }
if (args.Contains("--guard-check"))
{
    var path = Path.Combine(AppContext.BaseDirectory, "Wardogs-Win64-Shipping.exe");
    if (File.Exists(path)) throw new Exception("Fixture path already exists");
    File.Copy(Environment.ProcessPath!, path);
    try
    {
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path, "--guard-child")
            { UseShellExecute = false, CreateNoWindow = true })!;
        try
        {
            await Task.Delay(700);
            using var holder=System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!, $"--handle-owner {child.Id}")
                {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true})!;
            try
            {
                if(await holder.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))!="READY") throw new Exception("Fixture holder not ready");
                var result = await ExternalAccessCollector.CollectAsync(CancellationToken.None);
                if (child.HasExited) throw new Exception("Scanner terminated fixture process");
                if (!result.Evidence.Any(e=>Convert.ToInt32(e.Details["pid"])==holder.Id && Convert.ToInt32(e.Details["target_pid"])==child.Id))
                    throw new Exception("Synthetic external VM_READ handle not detected");
                var fixtureModules=new List<ModuleResult>();var moduleEvidence=new List<Evidence>();var errors=new List<string>();
                ModuleCollector.Collect(fixtureModules,moduleEvidence,errors,CancellationToken.None,child.Id);
                if(!moduleEvidence.Any(e=>e.Type=="loaded_module")) throw new Exception("Synthetic game modules not collected");
                if(!moduleEvidence.Any(e=>e.Type=="private_executable_memory")) throw new Exception("Game memory metadata not collected");
                Console.WriteLine($"PASS: running game allowed; synthetic external VM_READ detected; module={result.Module.Status}; checked={result.Module.ItemsChecked}; fixture untouched");
                Console.WriteLine($"PASS: synthetic game DLL inventory and memory-region metadata; module={fixtureModules.Single().Status}");
            }
            finally { if(!holder.HasExited) holder.Kill(); holder.WaitForExit(); }
        }
        finally { if (!child.HasExited) child.Kill(); child.WaitForExit(); }
    }
    finally { File.Delete(path); }
    return;
}
if (args.Contains("--hardware")) {
    Console.WriteLine("device identity kind="+(DeviceIdentityCollector.Collect()?.Kind ?? "unavailable"));
    var nativeModules = new List<ModuleResult>(); var nativeEvidence = new List<Evidence>(); var nativeErrors = new List<string>();
    HardwareCollector.Collect(nativeModules,nativeEvidence,nativeErrors,CancellationToken.None);
    if(nativeModules.Count!=2) throw new Exception("Hardware module count");
    foreach(var m in nativeModules) Console.WriteLine($"{m.Name}: {m.Status}; checked={m.ItemsChecked}");
    Console.WriteLine($"hardware evidence={nativeEvidence.Count}; errors={string.Join(",",nativeErrors)}");
    var testFolder=Path.Combine(Path.GetTempPath(),"WardogsJournalFixture-"+Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(testFolder);
    try {
        var parent=BrowserJournalCollector.DirectoryId(testFolder);
        var history=Path.Combine(testFolder,"History"); File.WriteAllText(history,"synthetic history fixture");File.Delete(history);
        var journal=BrowserJournalCollector.Read(Path.GetPathRoot(testFolder)!,CancellationToken.None);
        var own=journal.Traces.Where(t=>t.Parent==parent && t.Name=="History").ToList();
        Console.WriteLine($"journal coverage={journal.Coverage}; synthetic_delete_found={own.Any(t=>(t.Reason&0x200)!=0)}");
        if(journal.Coverage=="bounded_recent_window" && !own.Any(t=>(t.Reason&0x200)!=0)) throw new Exception("Native USN fixture mismatch");
    } finally { Directory.Delete(testFolder); }
    return;
}
if (!args.Contains("--live")) { FixtureChecks.Run(); ProcessContextFixtures.Offline(); UiHashFixture.Run(); return; }

var (processModule, processEvidence) = await ProcessCollector.CollectAsync(CancellationToken.None);
var forensic = await ForensicCollector.CollectAsync(CancellationToken.None);
var browser = await BrowserHistoryCollector.CollectAsync(CancellationToken.None);
var modules = new[] { processModule }.Concat(forensic.Modules).Append(browser.Module).ToList();
var evidence = EvidencePrioritizer.Select(processEvidence.Concat(forensic.Evidence).Concat(browser.Evidence));

var required = new[] {
    "processes", "services_drivers", "persistence", "security_posture", "tamper_indicators", "loaded_modules",
    "persistence_hooks", "recent_executables", "historical_execution", "browser_history", "cleanup",
};
foreach (var name in required)
    if (modules.Count(module => module.Name == name) != 1) throw new InvalidOperationException($"Missing or duplicate module: {name}");
if (evidence.Count > 500) throw new InvalidOperationException("Evidence limit exceeded.");
if (evidence.GroupBy(item => item.EvidenceId).Any(group => group.Count() > 1))
    throw new InvalidOperationException("Duplicate evidence identifiers detected.");
if (evidence.Any(item => item.EvidenceId.Length > 80 || item.Path.Length > 500 || item.Publisher.Length > 200))
    throw new InvalidOperationException("Evidence field limit exceeded.");
if (modules.Any(module => module.ItemsChecked < 0 || module.EndedAt < module.StartedAt))
    throw new InvalidOperationException("Invalid module metrics.");

Console.WriteLine($"PASS modules={modules.Count} evidence={evidence.Count} signals={evidence.Count(item => item.Severity != "none")}");
foreach (var module in modules) Console.WriteLine($"{module.Name}: {module.Status}, checked={module.ItemsChecked}, {module.Error}");

