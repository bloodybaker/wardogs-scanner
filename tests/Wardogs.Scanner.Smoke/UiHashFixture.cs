using System.Security.Cryptography;
using Wardogs.Scanner;

static class UiHashFixture
{
    private sealed class BlockedUiContext : SynchronizationContext
    {
        public int Posts;
        // Model a UI thread synchronously waiting for a hash: it cannot pump
        // posted callbacks. The old hash implementation deadlocked here.
        public override void Post(SendOrPostCallback callback, object? state) => Interlocked.Increment(ref Posts);
    }
    public static void Run()
    {
        var path=Path.Combine(Path.GetTempPath(),"wd-ui-hash-"+Guid.NewGuid().ToString("N")+".bin");
        var bytes=new byte[8*1024*1024]; RandomNumberGenerator.Fill(bytes);
        var expected=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        File.WriteAllBytes(path,bytes);
        var context=new BlockedUiContext(); Exception? error=null; string? result=null;
        using var done=new ManualResetEventSlim();
        var thread=new Thread(()=>
        {
            SynchronizationContext.SetSynchronizationContext(context);
            try { result=ProcessCollector.HashAsync(path,CancellationToken.None).GetAwaiter().GetResult(); }
            catch(Exception ex) { error=ex; }
            finally { done.Set(); }
        }) {IsBackground=true};
        try
        {
            thread.Start();
            if(!done.Wait(TimeSpan.FromSeconds(15))) throw new Exception("Hash deadlocked on UI synchronization context");
            if(error!=null) throw error;
            if(result!=expected || context.Posts!=0) throw new Exception("Hash posted to blocked UI or digest differs");
            Console.WriteLine("PASS UI synchronization regression: file hash completes without dispatching to blocked UI");
        }
        finally { File.Delete(path); }
    }
}
