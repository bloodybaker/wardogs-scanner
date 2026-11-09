using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace Wardogs.Scanner;

public static class MacroCollector
{
    private static readonly string[] Tools=["autohotkey","autoit3","pulovers","tinytask","macrorecorder","jitbit","xmousebuttoncontrol"];
    public static bool IsMacroTool(string name) => Tools.Any(tool=>name.StartsWith(tool,StringComparison.OrdinalIgnoreCase));
    public static string[] AnalyzeScript(string text)
    {
        if(text.Length>512000) return [];
        // Exclude whole-line comments. Return feature labels, never script text.
        text=Regex.Replace(text,@"(?m)^\s*(?:;|--|//|#).*?$","");
        bool movement=Regex.IsMatch(text,@"(?i)\b(?:MoveMouseRelative|MoveMouseTo|MouseMove|moveRel|mouse_event|SendInput|MouseClick|Click|PressMouseButton)\b");
        bool repeat=Regex.IsMatch(text,@"(?i)\b(?:while|for|loop|repeat|SetTimer)\b");
        bool trigger=Regex.IsMatch(text,@"(?i)(?:IsMouseButtonPressed|GetAsyncKeyState|GetKeyState|is_pressed|OnEvent|LButton|RButton|MOUSE_BUTTON_PRESSED)");
        bool context=Regex.IsMatch(text,@"(?i)(?:wardogs|вардог|no.?recoil|recoil|anti.?recoil|rapid.?fire|triggerbot|віддач|отдач)");
        if(!movement || !repeat) return [];
        var features=new List<string>{"repeated_mouse_input"};
        if(trigger) features.Add("input_trigger");
        if(context) features.Add("game_or_recoil_context");
        return features.ToArray();
    }
    public static Task<(ModuleResult Module,List<Evidence> Evidence)> CollectAsync(CancellationToken token)=>Task.Run(()=>Collect(token),token);
    private static (ModuleResult,List<Evidence>) Collect(CancellationToken token)
    {
        var start=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var items=new List<Evidence>();
        int checkedCount=0,failures=0;
        foreach(var process in Process.GetProcesses())
        using(process)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if(!IsMacroTool(process.ProcessName)) continue;
                string path=process.MainModule?.FileName??"";
                items.Add(new($"macro-tool-{process.Id}","macro_tool_running","macro_scripts",start,"UTC","scan_time",ProcessCollector.NormalizePath(path),"","","unknown",
                    "WD-MACRO-TOOL","none","high","Запущено інструмент автоматизації. Наявність програми не підтверджує активний макрос або використання в WARDOGS.",new(){["name"]=process.ProcessName,["pid"]=process.Id,["cheating_proof"]=false}));
                checkedCount++;
            }
            catch(Exception ex) when(ex is System.ComponentModel.Win32Exception or InvalidOperationException) { failures++; }
        }
        var home=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots=new[]{Path.Combine(home,"Downloads"),Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"AutoHotkey"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"LGHUB","scripts"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),"LGHUB","scripts")};
        var visited=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int enumerated=0;
        foreach(var root in roots.Where(Directory.Exists))
        {
            var pending=new Queue<(string,int)>(); pending.Enqueue((root,0));
            while(pending.Count>0 && enumerated<3000)
            {
                var (folder,depth)=pending.Dequeue();
                try
                {
                    if((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0) continue;
                    foreach(var file in Directory.EnumerateFiles(folder))
                    {
                        token.ThrowIfCancellationRequested();
                        if(++enumerated>3000) break;
                        if(!new[]{".ahk",".lua",".au3"}.Contains(Path.GetExtension(file).ToLowerInvariant()) || !visited.Add(file)) continue;
                        var info=new FileInfo(file);
                        if((info.Attributes&FileAttributes.ReparsePoint)!=0 || info.Length>512000) { failures++; continue; }
                        checkedCount++;
                        var signals=AnalyzeScript(File.ReadAllText(file));
                        if(signals.Length==0) continue;
                        var hash=ProcessCollector.HashAsync(file,token).GetAwaiter().GetResult();
                        items.Add(new("macro-script-"+hash[..24],"macro_script_candidate","macro_scripts",new DateTimeOffset(info.LastWriteTimeUtc).ToUnixTimeSeconds(),"UTC","historical",
                            ProcessCollector.NormalizePath(file),hash,"","not_applicable","WD-MACRO-REPEATED-INPUT",signals.Length==3?"medium":"low","medium",
                            "У скрипті знайдено ознаки повторюваного вводу миші. Час — зміна файла, не запуск. Вміст скрипта не передається; використання в грі потребує окремого підтвердження.",
                            new(){["features"]=string.Join(", ",signals),["execution_confirmed"]=false,["cheating_proof"]=false}));
                    }
                    if(depth<2) foreach(var child in Directory.EnumerateDirectories(folder).Take(100)) pending.Enqueue((child,depth+1));
                }
                catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { failures++; }
            }
        }
        if(enumerated>=3000) failures++;
        // This is always bounded static coverage, never a verdict on hardware
        // macros, encrypted vendor profiles or whether a script was activated.
        items.Add(new("macro-coverage","macro_scan_coverage","macro_scripts",start,"UTC","scan_time","","","","unknown","WD-MACRO-COVERAGE","none","unknown",
            "Перевірено запущені інструменти й доступні AHK/Lua/AutoIt-скрипти в Downloads, Desktop та відомих папках скриптів. Вбудовані макроси миші, зашифровані профілі й перейменовані/видалені скрипти можуть бути невидимі.",new(){["bounded"]=true,["file_limit"]=3000}));
        return (new("macro_scripts",failures>0?"partial":"success",start,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),checkedCount,
            failures>0?"Частина скриптів недоступна або досягнуто межі перевірки.":""),items.GroupBy(x=>x.EvidenceId).Select(g=>g.First()).ToList());
    }
}
