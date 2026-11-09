using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Wardogs.Scanner;

// Inspect handle metadata only. Never read/write game memory, inject code,
// duplicate handles, install drivers or request debug privileges.
public static class ExternalAccessCollector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct HandleEntry
    {
        public IntPtr Object;
        public UIntPtr ProcessId, Handle;
        public uint Access;
        public ushort BackTrace, Type;
        public uint Attributes, Reserved;
    }
    [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int info, IntPtr buffer, int length, out int needed);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    public static bool IsMemoryAccess(uint mask) => (mask & (0x10u|0x20u|0x8u|0x2u)) != 0;
    public static string AccessLabel(uint mask) => string.Join(", ", new[]{
        (0x10u,"VM_READ"),(0x20u,"VM_WRITE"),(0x8u,"VM_OPERATION"),(0x2u,"CREATE_THREAD")}
        .Where(x=>(mask&x.Item1)!=0).Select(x=>x.Item2));

    public static Task<(ModuleResult Module,List<Evidence> Evidence)> CollectAsync(CancellationToken token) => Task.Run(()=>Collect(token),token);
    private static (ModuleResult,List<Evidence>) Collect(CancellationToken token)
    {
        var start=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var evidence=new List<Evidence>();
        var targets=new Dictionary<IntPtr,int>();
        var gamePids=new HashSet<int>();
        int failures=0, checkedCount=0;
        IntPtr buffer=IntPtr.Zero;
        try
        {
            foreach(var process in Process.GetProcesses())
            using(process)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    if(!GameProcessGuard.IsGameProcess(process.ProcessName)) continue;
                    gamePids.Add(process.Id);
                    var handle=OpenProcess(0x1000,false,process.Id);
                    if(handle!=IntPtr.Zero) targets[handle]=process.Id; else failures++;
                }
                catch(InvalidOperationException) { failures++; }
            }
            if(gamePids.Count==0) return (new("external_process_access","skipped",start,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),0,"WARDOGS не запущено; доступ сторонніх процесів до гри зараз не перевіряється."),evidence);
            if(!Environment.Is64BitProcess) throw new NotSupportedException();
            int size=4*1024*1024, status, needed;
            while(true)
            {
                token.ThrowIfCancellationRequested();
                buffer=Marshal.AllocHGlobal(size);
                status=NtQuerySystemInformation(64,buffer,size,out needed);
                if(status==0) break;
                Marshal.FreeHGlobal(buffer); buffer=IntPtr.Zero;
                if(status!=unchecked((int)0xC0000004) || size>=64*1024*1024) throw new InvalidOperationException("Handle metadata unavailable");
                size=Math.Min(64*1024*1024,Math.Max(size*2,needed+65536));
            }
            long count=Marshal.ReadInt64(buffer);
            int entrySize=Marshal.SizeOf<HandleEntry>();
            if(count<0 || count>(size-16)/entrySize) throw new InvalidOperationException("Invalid handle table");
            var objects=new Dictionary<IntPtr,int>();
            for(int i=0;i<count;i++)
            {
                var entry=Marshal.PtrToStructure<HandleEntry>(buffer+16+i*entrySize);
                if(entry.ProcessId.ToUInt64()==(ulong)Environment.ProcessId && targets.TryGetValue((IntPtr)(long)entry.Handle.ToUInt64(),out var pid) && entry.Object!=IntPtr.Zero)
                    objects[entry.Object]=pid;
            }
            if(objects.Count<targets.Count || targets.Count==0) failures++;
            var owners=new Dictionary<(int Owner,int Target),uint>();
            for(int i=0;i<count;i++)
            {
                token.ThrowIfCancellationRequested();
                var entry=Marshal.PtrToStructure<HandleEntry>(buffer+16+i*entrySize);
                if(!objects.TryGetValue(entry.Object,out var target) || entry.ProcessId.ToUInt64()>int.MaxValue) continue;
                checkedCount++;
                int owner=(int)entry.ProcessId.ToUInt64();
                if(owner<=4 || owner==Environment.ProcessId || gamePids.Contains(owner) || !IsMemoryAccess(entry.Access)) continue;
                owners[(owner,target)]=owners.GetValueOrDefault((owner,target))|entry.Access;
            }
            foreach(var pair in owners.Take(100))
            {
                string path="", name="unavailable", hash="", publisher="", signature="unknown";
                try
                {
                    using var owner=Process.GetProcessById(pair.Key.Owner);
                    name=owner.ProcessName;
                    path=owner.MainModule?.FileName ?? "";
                    if(path.Length>0)
                    {
                        (publisher,signature)=ProcessCollector.ReadSignature(path);
                        hash=ProcessCollector.HashAsync(path,token).GetAwaiter().GetResult();
                        path=ProcessCollector.NormalizePath(path);
                    }
                }
                catch(Exception ex) when(ex is System.ComponentModel.Win32Exception or ArgumentException or InvalidOperationException or System.IO.IOException or UnauthorizedAccessException) { failures++; }
                evidence.Add(new($"external-{pair.Key.Owner}-{pair.Key.Target}","external_process_handle","external_process_access",start,"UTC","scan_time",path,hash,publisher,signature,
                    "WD-EXTERNAL-GAME-HANDLE","medium","high",
                    "Сторонній процес має дескриптор WARDOGS із правами доступу до пам’яті/створення потоку. Це можливість доступу, а не доказ фактичного читання чи чита: аналогічні права мають антивіруси, оверлеї та діагностика.",
                    new(){["pid"]=pair.Key.Owner,["target_pid"]=pair.Key.Target,["name"]=name,["access_mask"]=$"0x{pair.Value:X8}",["access_rights"]=AccessLabel(pair.Value),["cheating_proof"]=false}));
            }
            if(owners.Count>100) failures++;
        }
        catch(Exception ex) when(ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception) { failures++; }
        finally
        {
            if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            foreach(var handle in targets.Keys) CloseHandle(handle);
        }
        return (new("external_process_access",failures>0?"partial":"success",start,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),checkedCount,
            failures>0?"Частина метаданих дескрипторів/процесів недоступна; відсутність збігів не виключає external або DMA.":""),evidence);
    }
}
