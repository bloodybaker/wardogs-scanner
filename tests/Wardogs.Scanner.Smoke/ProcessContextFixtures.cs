using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Wardogs.Scanner;

static class ProcessContextFixtures
{
    private static void Check(bool pass,string name) { if(!pass) throw new Exception(name); }
    public static void Offline()
    {
        Check(ProcessContextCollector.IdentityState("Steam.exe","Valve Corp.","valid_offline")=="expected_publisher_verified","Valve identity");
        Check(ProcessContextCollector.IdentityState("Steam.exe","Valve Corp.","unsigned")=="signature_not_verified","Publisher text alone cannot verify identity");
        Check(ProcessContextCollector.IdentityState("OneDrive.exe","Unrelated Publisher","valid_offline")=="publisher_mismatch","Wrong but valid publisher");
        Check(ProcessContextCollector.IdentityState("Photoshop.exe","Adobe Inc.","valid_offline")=="expected_publisher_verified","Adobe identity");
        Check(ModuleCollector.IsReviewHost("OneDrive") && ModuleCollector.IsReviewHost("Photoshop"),"Review modules of impersonated hosts");
        var parent=new ProcessContextCollector.Row(100,99,"cmd.exe","","",100);
        var child=new ProcessContextCollector.Row(101,100,"python.exe","","",101);
        Check(ProcessContextCollector.ValidParent(child,parent),"Parent lifetime");
        Check(!ProcessContextCollector.ValidParent(child,parent with {Created=102}),"Reused parent PID rejected");
        Check(!ProcessContextCollector.ValidParent(child,parent with {Created=0}),"Unknown parent lifetime rejected");
        var command="python.exe \"D:\\macro folder\\test.py\" --secret PRIVATE_SENTINEL";
        Check(ProcessContextCollector.ScriptPaths(command).Single()==@"D:\macro folder\test.py","Quoted absolute script path");
        Check(ProcessContextCollector.ScriptPaths(@"python.exe D:\test.py").Single()==@"D:\test.py","Unquoted absolute script path");
        Check(ProcessContextCollector.ScriptPaths("python.exe relative.py https://example.com/test.py").Length==0,"No incorrect relative or remote file resolution");
        var macro="while keyboard.is_pressed('left'): pyautogui.moveRel(0, recoil)";
        Check(MacroCollector.AnalyzeScript(macro).Length==3,"Python macro features");
        Check(MacroCollector.AnalyzeScript("while True: pyautogui.click()").Length==1,"Ungated autoclick loop");
        Check(MacroCollector.AnalyzeScript("# while True: pyautogui.click()").Length==0,"Python comment excluded");
        Check(MacroCollector.AnalyzeScript("print('hello')").Length==0,"Benign script");
        var encoded="powershell.exe -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(macro));
        Check(ProcessContextCollector.LocalScriptText("powershell.exe",encoded)==macro,"Local encoded-command analysis");
        var path=Path.Combine(Path.GetTempPath(),"wd-context-fixture-"+Guid.NewGuid().ToString("N")+".py");
        try
        {
            File.WriteAllText(path,macro+"\n# PRIVATE_SCRIPT_SENTINEL");
            var rows=new[]{parent,child with {Command=$"python.exe \"{path}\" --secret PRIVATE_SENTINEL"}};
            var result=ProcessContextCollector.Analyze(rows,CancellationToken.None);
            var evidence=result.Evidence.Single(e=>e.Type=="macro_launch_candidate");
            Check((string)evidence.Details["parent_name"]! == "cmd.exe","cmd launch relation preserved");
            Check(evidence.Sha256.Length==64,"Referenced script fingerprinted");
            Check(!(bool)evidence.Details["execution_confirmed"]!,"Reference is not proof of execution");
            var json=JsonSerializer.Serialize(result.Evidence);
            Check(!json.Contains("PRIVATE_SENTINEL") && !json.Contains("PRIVATE_SCRIPT_SENTINEL") && !json.Contains("pyautogui"),"No raw command or content export");
            File.WriteAllText(path,"print('hello')");
            Check(!ProcessContextCollector.Analyze(rows,CancellationToken.None).Evidence.Any(),"Benign cmd script does not flag");
            File.Delete(path);
            Check(ProcessContextCollector.Analyze(rows,CancellationToken.None).Module.Status=="partial","Missing script is partial");
        }
        finally { if(File.Exists(path)) File.Delete(path); }
        Console.WriteLine("PASS 22 process-context fixtures (identity, cmd/script reference, privacy, PID reuse, benign/missing script)");
    }
    public static async Task Native()
    {
        // All copied EXEs run this inert fixture apphost; no macro is executed.
        var files=new[]{"Steam.exe","python.exe","Wardogs-Win64-Shipping.exe"}.Select(n=>Path.Combine(AppContext.BaseDirectory,n)).ToArray();
        if(files.Any(File.Exists)) throw new Exception("Fixture file collision");
        var script=Path.Combine(Path.GetTempPath(),"wd-launch-"+Guid.NewGuid().ToString("N")+".py");
        var launched=new List<Process>(); var children=new List<Process>();
        try
        {
            foreach(var file in files) File.Copy(Environment.ProcessPath!,file);
            File.WriteAllText(script,"while keyboard.is_pressed('left'): pyautogui.moveRel(0, recoil)\n# PRIVATE_SCRIPT_SENTINEL");
            var game=Process.Start(new ProcessStartInfo(files[2],"--guard-child") { UseShellExecute=false,CreateNoWindow=true })!;
            children.Add(game);
            Process Launch(string executable,string arguments)
            {
                if(executable.Contains('"') || executable.Contains('%') || executable.Contains('!')) throw new Exception("Unsafe fixture path");
                var process=Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"cmd.exe"),$"/d /s /c \"\"{executable}\" {arguments}\"")
                {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true})!;
                launched.Add(process); return process;
            }
            var holder=Launch(files[0],$"--handle-owner {game.Id}");
            if(await holder.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(8))!="READY") throw new Exception("Holder not ready");
            var python=Launch(files[1],$"--guard-child \"{script}\" --secret PRIVATE_SENTINEL");
            await Task.Delay(400);
            var snapshot=await ProcessContextCollector.SnapshotAsync(CancellationToken.None);
            var selected=snapshot.Where(r=>files.Contains(r.Path,StringComparer.OrdinalIgnoreCase) || launched.Any(p=>p.Id==r.Pid)).ToList();
            foreach(var row in selected.Where(r=>!launched.Any(p=>p.Id==r.Pid) && r.Pid!=game.Id)) children.Add(Process.GetProcessById(row.Pid));
            var result=ProcessContextCollector.Analyze(selected,CancellationToken.None);
            var identity=result.Evidence.Single(e=>e.Type=="process_identity" && (string)e.Details["name"]! == "Steam.exe");
            Check(identity.Severity=="low" && identity.Sha256.Length==64,"Renamed Steam identity detected");
            Check((string)identity.Details["parent_name"]! == "cmd.exe","Native cmd parent verified");
            var macro=result.Evidence.Single(e=>e.Type=="macro_launch_candidate");
            Check((string)macro.Details["parent_name"]! == "cmd.exe","Native cmd macro reference detected");
            var access=await ExternalAccessCollector.CollectAsync(CancellationToken.None);
            Check(access.Evidence.Any(e=>Convert.ToInt32(e.Details["pid"])==Convert.ToInt32(identity.Details["pid"]) && Convert.ToInt32(e.Details["target_pid"])==game.Id),"Renamed Steam game handle detected");
            Check(!JsonSerializer.Serialize(result.Evidence).Contains("PRIVATE_SENTINEL"),"Native command arguments not exported");
            Check(!game.HasExited,"Game fixture remains alive");
            Console.WriteLine("PASS native: cmd -> renamed Steam with game handle; cmd -> inert Python with macro script reference; verified parent times; no raw command export");
        }
        finally
        {
            foreach(var process in launched.Concat(children)) { try { if(!process.HasExited) process.Kill(true); process.WaitForExit(); } catch(InvalidOperationException) {} finally { process.Dispose(); } }
            // Only these exact files were created above; no directory removal.
            foreach(var file in files.Append(script)) if(File.Exists(file)) File.Delete(file);
        }
    }
}
