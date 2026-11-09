using System.Runtime.InteropServices;

static class NativeFixture
{
    [DllImport("kernel32.dll",SetLastError=true)] private static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    public static void Hold(int pid)
    {
        var handle=OpenProcess(0x1010,false,pid);
        if(handle==IntPtr.Zero) throw new Exception("Cannot open synthetic fixture");
        try { Console.WriteLine("READY"); Console.Out.Flush(); Thread.Sleep(60000); }
        finally { CloseHandle(handle); }
    }
}
