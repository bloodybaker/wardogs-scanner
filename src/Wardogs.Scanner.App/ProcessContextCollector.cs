using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Wardogs.Scanner;

// Command lines are inspected locally. Never include raw arguments or script
// contents in evidence; scripts are read as data and are never executed.
public static class ProcessContextCollector
{
    public sealed record Row(int Pid, int Parent, string Name, string Path, string Command, double Created);
    public static bool IsInterpreter(string name) => Regex.IsMatch(name,
        @"^(?:cmd|powershell|pwsh|python(?:w|\d+(?:\.\d+)?)?|py|wscript|cscript|autohotkey.*|autoit3.*)\.exe$", RegexOptions.IgnoreCase);
    public static string ExpectedPublisher(string name) => name.ToLowerInvariant() switch
    {
        "steam.exe" or "steamwebhelper.exe" => "Valve Corp.",
        "onedrive.exe" => "Microsoft Corporation",
        "photoshop.exe" => "Adobe Inc.",
        "discord.exe" or "discordcanary.exe" or "discordptb.exe" => "Discord Inc.",
        _ => ""
    };
    public static string IdentityState(string name, string publisher, string signature) =>
        ExpectedPublisher(name) is var expected && expected.Length > 0
        ? signature != "valid_offline" ? "signature_not_verified"
          : publisher.Equals(expected, StringComparison.OrdinalIgnoreCase) ||
            (expected == "Adobe Inc." && publisher == "Adobe Systems Incorporated") ||
            (expected == "Valve Corp." && publisher == "Valve Corporation") ||
            (expected == "Discord Inc." && publisher == "Discord, Inc.")
              ? "expected_publisher_verified" : "publisher_mismatch"
        : "not_applicable";
    public static bool ValidParent(Row child, Row parent) => child.Parent == parent.Pid && child.Pid != parent.Pid &&
        parent.Created > 0 && child.Created > 0 && parent.Created <= child.Created;
    public static string[] ScriptPaths(string command) => Regex.Matches(command,
        "(?:\"(?<p>[A-Za-z]:\\\\[^\"\\r\\n]+\\.(?:ahk|au3|lua|ps1|py|vbs|js|bat|cmd))\"|(?<![\\w:/\\\\])(?<p>[A-Za-z]:\\\\[^\\s\"<>|]+\\.(?:ahk|au3|lua|ps1|py|vbs|js|bat|cmd))(?=\\s|$))", RegexOptions.IgnoreCase)
        .Select(m => m.Groups["p"].Value).Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToArray();
    public static string LocalScriptText(string name, string command)
    {
        if (!name.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) && !name.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)) return command;
        var match = Regex.Match(command, @"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]{4,12000})(?:\s|$)");
        if (!match.Success) return command;
        try { return Encoding.Unicode.GetString(Convert.FromBase64String(match.Groups[1].Value)); }
        catch (FormatException) { return ""; }
    }
    private const string SnapshotScript = """
        $ErrorActionPreference='Stop'
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding
        $rows=@(Get-CimInstance Win32_Process -OperationTimeoutSec 15 | Select-Object -First 4097)
        @($rows | ForEach-Object {
            $cmd=[string]$_.CommandLine
            @{Pid=[int]$_.ProcessId;Parent=[int]$_.ParentProcessId;Name=[string]$_.Name;Path=[string]$_.ExecutablePath;
              Command=$(if($cmd.Length -le 16384){$cmd}else{''});
              Created=$(if($_.CreationDate){([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds()/1000.0}else{0})}
        }) | ConvertTo-Json -Depth 3 -Compress
        """;
    public static async Task<List<Row>> SnapshotAsync(CancellationToken token)
    {
        var info = new ProcessStartInfo(System.IO.Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute=false, CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true, StandardOutputEncoding=Encoding.UTF8 };
        foreach(var arg in new[]{"-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes(SnapshotScript))}) info.ArgumentList.Add(arg);
        using var process=Process.Start(info) ?? throw new IOException("Process snapshot unavailable");
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var output=ReadBoundedAsync(process.StandardOutput,8_000_000,timeout.Token);
            var errors=ReadBoundedAsync(process.StandardError,32000,timeout.Token);
            await Task.WhenAll(output,errors,process.WaitForExitAsync(timeout.Token));
            if(process.ExitCode!=0) throw new IOException("Process snapshot failed");
            return JsonSerializer.Deserialize<List<Row>>(await output) ?? [];
        }
        finally { if(!process.HasExited) process.Kill(); }
    }
    private static async Task<string> ReadBoundedAsync(StreamReader reader,int limit,CancellationToken token)
    {
        var buffer=new char[8192]; var result=new StringBuilder(); int count;
        while((count=await reader.ReadAsync(buffer.AsMemory(),token))>0)
        { if(result.Length+count>limit) throw new IOException("Snapshot size limit"); result.Append(buffer,0,count); }
        return result.ToString();
    }
    public static Task<(ModuleResult Module,List<Evidence> Evidence)> CollectAsync(CancellationToken token) =>
        Task.Run(() => CollectCoreAsync(token), token);

    private static async Task<(ModuleResult Module,List<Evidence> Evidence)> CollectCoreAsync(CancellationToken token)
    {
        var start=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        try { return Analyze(await SnapshotAsync(token),token); }
        catch(Exception ex) when(ex is IOException or JsonException or OperationCanceledException or System.ComponentModel.Win32Exception)
        {
            token.ThrowIfCancellationRequested();
            return (new("process_context","partial",start,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),0,"Походження процесів недоступне або запит перевищив час очікування."),[]);
        }
    }
    public static (ModuleResult Module,List<Evidence> Evidence) Analyze(IReadOnlyList<Row> rows,CancellationToken token)
    {
        var start=DateTimeOffset.UtcNow.ToUnixTimeSeconds(); var evidence=new List<Evidence>(); int failures=rows.Count>4096?1:0,checkedCount=0;
        var lookup=rows.GroupBy(r=>r.Pid).ToDictionary(g=>g.Key,g=>g.First());
        foreach(var row in rows.Take(4096))
        {
            token.ThrowIfCancellationRequested();
            if(row.Pid==Environment.ProcessId || row.Parent==Environment.ProcessId) continue;
            var interpreter=IsInterpreter(row.Name);
            var interpreterName=row.Name;
            bool identity=ExpectedPublisher(row.Name).Length>0;
            bool macroTool=MacroCollector.IsMacroTool(row.Name);
            if(!interpreter && !identity && !macroTool)
            {
                // Recognize a renamed interpreter from its file metadata too.
                try
                {
                    if(!File.Exists(row.Path)) continue;
                    var version=FileVersionInfo.GetVersionInfo(row.Path);
                    macroTool=MacroCollector.IsMacroTool(version.OriginalFilename??"") || MacroCollector.IsMacroTool(version.ProductName??"");
                    interpreter=IsInterpreter(version.OriginalFilename??"");
                    if(interpreter) interpreterName=version.OriginalFilename!;
                    if(!macroTool && !interpreter) continue;
                }
                catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { failures++; continue; }
            }
            if(evidence.Count>=200) { failures++; break; }
            checkedCount++;
            try
            {
                var details=new Dictionary<string,object?> { ["pid"]=row.Pid,["name"]=row.Name,["cheating_proof"]=false,["execution_confirmed"]=false };
                if(lookup.TryGetValue(row.Parent,out var parent) && ValidParent(row,parent))
                { details["parent_pid"]=parent.Pid; details["parent_name"]=parent.Name; details["parent_verified"]=true; }
                else { details["parent_verified"]=false; failures++; }
                if(identity || macroTool)
                {
                    if(!File.Exists(row.Path)) { failures++; continue; }
                    var metadata=FileVersionInfo.GetVersionInfo(row.Path);
                    if(IsInterpreter(metadata.OriginalFilename??"")) { interpreter=true; interpreterName=metadata.OriginalFilename!; }
                    var (publisher,signature)=ProcessCollector.ReadSignature(row.Path);
                    var hash=new FileInfo(row.Path).Length<=100_000_000?ProcessCollector.HashAsync(row.Path,token).GetAwaiter().GetResult():"";
                    if(hash.Length==0) failures++;
                    details["original_filename"]=Limit(metadata.OriginalFilename??"");
                    details["product_name"]=Limit(metadata.ProductName??"");
                    details["identity_state"]=IdentityState(row.Name,publisher,signature);
                    details["expected_publisher"]=ExpectedPublisher(row.Name);
                    // Version strings are self-declared, never trust anchors.
                    var macroIdentity=MacroCollector.IsMacroTool(metadata.OriginalFilename??"") || MacroCollector.IsMacroTool(metadata.ProductName??"");
                    details["macro_metadata"]=macroIdentity;
                    var suspicious=identity && IdentityState(row.Name,publisher,signature)!="expected_publisher_verified";
                    evidence.Add(new($"identity-{row.Pid}","process_identity","process_context",start,"UTC","scan_time",Limit(ProcessCollector.NormalizePath(row.Path)),hash,Limit(publisher,200),signature,
                        "WD-PROCESS-IDENTITY",suspicious?"low":"none","medium",
                        "Перевірено підпис видавця та метадані файла. Невідповідність назві потребує перевірки; підписаний файл не виключає інжект у процес. Метадані можна підробити.",new(details)));
                }
                if(!interpreter) continue;
                if(string.IsNullOrWhiteSpace(row.Command)) { failures++; continue; }
                var local=LocalScriptText(interpreterName,row.Command);
                var inline=MacroCollector.AnalyzeScript(local);
                if(inline.Length>0) AddMacro(evidence,row,details,"", "",inline,start,"Аргументи запуску містять ознаки повторюваного вводу. Командний рядок аналізувався локально й не передається; виконання цих інструкцій не доведено.");
                var paths=ScriptPaths(local);
                if(paths.Length==8) failures++;
                foreach(var file in paths)
                {
                    try
                    {
                        var info=new FileInfo(file);
                        if(!info.Exists || (info.Attributes&FileAttributes.ReparsePoint)!=0 || info.Length>512000) { failures++; continue; }
                        // Bound the opened stream as well, in case the file changes.
                        using var reader=new StreamReader(new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete));
                        var content=ReadBoundedAsync(reader,512000,token).GetAwaiter().GetResult();
                        var features=MacroCollector.AnalyzeScript(content);
                        if(features.Length==0) continue;
                        var hash=ProcessCollector.HashAsync(file,token).GetAwaiter().GetResult();
                        AddMacro(evidence,row,details,Limit(ProcessCollector.NormalizePath(file)),hash,features,start,"У скрипті, вказаному в аргументах активного процесу, знайдено ознаки повторюваного вводу. Вміст скрипта не передається; активація макроса й використання в грі не доведені.");
                    }
                    catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { failures++; }
                }
                // Unresolved relative paths and encoded/unrecognized arguments cannot be called complete.
                if(paths.Length==0 && inline.Length==0) failures++;
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { failures++; }
        }
        return (new("process_context",failures>0?"partial":"success",start,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),checkedCount,
            failures>0?"Частина аргументів, файлів або батьківських процесів недоступна. Закриті процеси, відносні шляхи та прихований код можуть залишитися невидимими.":""),evidence);
    }
    private static void AddMacro(List<Evidence> evidence,Row row,Dictionary<string,object?> context,string path,string hash,string[] features,double now,string explanation)
    {
        var details=new Dictionary<string,object?>(context) { ["features"]=string.Join(", ",features),["launch_reference_observed"]=true };
        evidence.Add(new($"launch-macro-{row.Pid}-{(hash.Length>0?hash[..16]:"inline")}","macro_launch_candidate","process_context",now,"UTC","scan_time",path,hash,"","unknown",
            "WD-MACRO-LAUNCH",features.Length==3?"medium":"low","medium",explanation,details));
    }
    private static string Limit(string value,int max=500)=>value.Length>max?value[..max]:value;
}
