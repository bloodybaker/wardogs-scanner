using System.Runtime.InteropServices;

namespace Wardogs.Scanner;

public static class SignatureVerifier
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    private struct FileInfo { public uint Size; public string Path; public IntPtr FileHandle,KnownSubject; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size; public IntPtr PolicyCallback,SipClient;
        public uint UiChoice,RevocationChecks,UnionChoice;
        public IntPtr File; public uint StateAction; public IntPtr StateData,UrlReference;
        public uint ProviderFlags,UiContext; public IntPtr SignatureSettings;
    }
    [DllImport("wintrust.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
    private static extern int WinVerifyTrust(IntPtr window,[In] ref Guid action,ref TrustData data);
    public static string Verify(string path)
    {
        var file=new FileInfo{Size=(uint)Marshal.SizeOf<FileInfo>(),Path=path};
        var pointer=Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
        Marshal.StructureToPtr(file,pointer,false);
        var action=new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var data=new TrustData{Size=(uint)Marshal.SizeOf<TrustData>(),UiChoice=2,UnionChoice=1,File=pointer,StateAction=1,
            ProviderFlags=0x1000|0x10}; // Offline cache only; no network revocation request.
        try
        {
            var result=WinVerifyTrust(new IntPtr(-1),ref action,ref data);
            return result==0?"valid_offline":result==unchecked((int)0x800B0100)?"unsigned":"invalid_or_untrusted";
        }
        finally
        {
            data.StateAction=2;WinVerifyTrust(new IntPtr(-1),ref action,ref data);
            Marshal.DestroyStructure<FileInfo>(pointer);Marshal.FreeHGlobal(pointer);
        }
    }
}
