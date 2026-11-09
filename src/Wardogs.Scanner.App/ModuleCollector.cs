using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace Wardogs.Scanner;

public static class ModuleCollector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryInfo
    {
        public IntPtr BaseAddress,AllocationBase;
        public uint AllocationProtect,Alignment1;
        public UIntPtr RegionSize;
        public uint State,Protect,Type,Alignment2;
    }
    [DllImport("kernel32.dll",SetLastError=true)] private static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern UIntPtr VirtualQueryEx(IntPtr process,IntPtr address,out MemoryInfo info,UIntPtr length);
    public static bool PrivateExecutable(uint state,uint type,uint protect) =>
        state==0x1000 && type==0x20000 && (protect&0xF0)!=0 && (protect&0x100)==0;
    public static bool IsOverlay(string name) => name.Equals("Discord",StringComparison.OrdinalIgnoreCase)
        || name.Equals("DiscordCanary",StringComparison.OrdinalIgnoreCase)
        || name.Equals("DiscordPTB",StringComparison.OrdinalIgnoreCase);
    public static bool IsReviewHost(string name) => IsOverlay(name) ||
        new[]{"Steam","OneDrive","Photoshop"}.Contains(name,StringComparer.OrdinalIgnoreCase);

    public static void Collect(List<ModuleResult> modules,List<Evidence> evidence,List<string> errors,CancellationToken token,int? fixturePid=null)
    {
        var start=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        int checkedCount=0,failures=0,targets=0;
        var signatures=new Dictionary<string,(string,string,string)>(StringComparer.OrdinalIgnoreCase);
        foreach(var process in Process.GetProcesses())
        using(process)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if(fixturePid.HasValue && process.Id!=fixturePid.Value) continue;
                bool game=GameProcessGuard.IsGameProcess(process.ProcessName);
                if(!game && !IsReviewHost(process.ProcessName)) continue;
                if(++targets>24) {failures++;break;}
                var image=process.MainModule?.FileName??"";
                var folder=Path.GetDirectoryName(image)??"";
                var windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows)+Path.DirectorySeparatorChar;
                var loaded=process.Modules;
                foreach(ProcessModule module in loaded)
                {
                    token.ThrowIfCancellationRequested();
                    if(++checkedCount>1500) {failures++;break;}
                    string file=module.FileName;
                    bool outside=!file.StartsWith(folder+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)
                        && !file.StartsWith(windows,StringComparison.OrdinalIgnoreCase);
                    // System DLL inventory adds noise. Record game/app modules
                    // and every external DLL, regardless of the process name.
                    if(file.StartsWith(windows,StringComparison.OrdinalIgnoreCase)) continue;
                    if(!signatures.TryGetValue(file,out var meta))
                    {
                        var (publisher,signature)=ProcessCollector.ReadSignature(file);
                        var hash=new FileInfo(file).Length<=100_000_000?ProcessCollector.HashAsync(file,token).GetAwaiter().GetResult():"";
                        signatures[file]=meta=(publisher,signature,hash);
                    }
                    var digest=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(file))).ToLowerInvariant()[..20];
                    evidence.Add(new($"module-{process.Id}-{digest}","loaded_module","loaded_modules",start,"UTC","scan_time",ProcessCollector.NormalizePath(file),meta.Item3,meta.Item1,meta.Item2,
                        outside?"WD-MODULE-EXTERNAL-PATH":"WD-MODULE-INVENTORY",outside?"low":"none",outside?"medium":"unknown",
                        outside?"DLL завантажено з-поза папки процесу та Windows. Це може бути легальний Discord/Steam/драйверний оверлей або сторонній модуль; потрібна перевірка хеша й походження. Сам оверлей не є читом."
                            :"Завантажений модуль гри або перевірюваної програми зафіксовано для кореляції хеша та підпису; наявність не є доказом чита.",
                        new(){["pid"]=process.Id,["process_name"]=process.ProcessName,["outside_installation"]=outside,["cheating_proof"]=false}));
                }
                if(game)
                {
                    var memory=MemoryMetadata(process.Id,token);
                    if(!memory.Complete) failures++;
                    evidence.Add(new($"private-exec-{process.Id}","private_executable_memory","loaded_modules",start,"UTC","scan_time","","","","unknown",
                        "WD-GAME-PRIVATE-EXEC",memory.Count>0?"medium":"none","medium",
                        "Метадані виконуваних приватних ділянок процесу гри. Такі ділянки можуть створювати інжектори, JIT або захисне ПЗ; самі по собі не доводять чит. Вміст пам’яті не читається й не передається.",
                        new(){["pid"]=process.Id,["regions"]=memory.Count,["bytes"]=memory.Bytes,["complete"]=memory.Complete,["cheating_proof"]=false}));
                }
            }
            catch(Exception ex) when(ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException)
            { failures++; errors.Add("loaded_modules: "+ex.GetType().Name); }
        }
        modules.Add(new("loaded_modules",targets==0?"skipped":failures>0?"partial":"success",start,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),checkedCount,
            targets==0?"Гру та перевірювані програми не знайдено.":failures>0?"Частина модулів або метаданих пам’яті недоступна. Захист не обходився.":""));
    }
    private static (int Count,long Bytes,bool Complete) MemoryMetadata(int pid,CancellationToken token)
    {
        var handle=OpenProcess(0x400,false,pid); // QUERY_INFORMATION only; no VM_READ.
        if(handle==IntPtr.Zero) return (0,0,false);
        int count=0;long bytes=0,address=0;var watch=Stopwatch.StartNew();
        try
        {
            for(int i=0;i<50000 && watch.Elapsed.TotalSeconds<5;i++)
            {
                token.ThrowIfCancellationRequested();
                if(VirtualQueryEx(handle,(IntPtr)address,out var info,(UIntPtr)Marshal.SizeOf<MemoryInfo>())==UIntPtr.Zero)
                    return (count,bytes,Marshal.GetLastWin32Error()==87 && address>0);
                long length=(long)info.RegionSize.ToUInt64();
                if(length<=0 || info.BaseAddress.ToInt64()>long.MaxValue-length) return (count,bytes,false);
                if(PrivateExecutable(info.State,info.Type,info.Protect)) {count++;bytes+=length;}
                long next=info.BaseAddress.ToInt64()+length;
                if(next<=address) return (count,bytes,false);
                address=next;
            }
            return (count,bytes,false);
        }
        finally {CloseHandle(handle);}
    }
}
