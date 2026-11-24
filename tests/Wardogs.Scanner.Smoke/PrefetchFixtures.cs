using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Wardogs.Scanner;

static class PrefetchFixtures
{
    static void Check(bool ok, string name) { if (!ok) throw new Exception(name); }
    static void Invalid(byte[] data)
    {
        try { PrefetchReader.Parse(data, new Dictionary<string,string>()); }
        catch (System.IO.InvalidDataException) { return; }
        throw new Exception("Malformed Prefetch accepted");
    }
    static byte[] Fixture(int version, int metrics, string[] paths)
    {
        var names = Encoding.Unicode.GetBytes(string.Join('\0', paths) + "\0");
        var data = new byte[metrics + names.Length];
        void U32(int offset, int value) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), (uint)value);
        U32(0,version); U32(4,0x41434353); U32(12,data.Length); U32(84,metrics);
        Encoding.Unicode.GetBytes("TOOL.EXE").CopyTo(data,16);
        U32(100,metrics); U32(104,names.Length);
        U32(version==17?144:version==23?152:metrics==296?200:208,37);
        int timeOffset=version==17?120:128;
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(timeOffset),new DateTime(2026,1,2,3,4,5,DateTimeKind.Utc).ToFileTimeUtc());
        if(version>=26) BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(timeOffset+8),new DateTime(2026,1,1,3,4,5,DateTimeKind.Utc).ToFileTimeUtc());
        names.CopyTo(data,metrics);
        return data;
    }
    public static void Run()
    {
        var mappings = new Dictionary<string,string> { [@"\DEVICE\HARDDISKVOLUME8"] = "E:" };
        foreach (var (version,metrics) in new[]{(17,152),(23,240),(26,304),(30,304),(30,296),(31,296)})
        {
            var data=Fixture(version,metrics,[@"\DEVICE\HARDDISKVOLUME8\Загрузки\TOOL.EXE",@"\DEVICE\HARDDISKVOLUME8\Windows\System32\KERNEL32.DLL"]);
            var parsed=PrefetchReader.Parse(data,mappings);
            Check(parsed.ProcessPath==@"E:\Загрузки\TOOL.EXE" && parsed.RunCount==37 && parsed.RunTimes.Length==(version>=26?2:1),"Prefetch version "+version);
            var compressed=Compress(data);
            Check(PrefetchReader.Parse(compressed,mappings)==parsed || PrefetchReader.Parse(compressed,mappings).ProcessPath==parsed.ProcessPath,"MAM roundtrip");
            Invalid(data[..100]);
            var corrupt=(byte[])data.Clone();BinaryPrimitives.WriteUInt32LittleEndian(corrupt.AsSpan(100),uint.MaxValue);Invalid(corrupt);
        }
        var ambiguous=PrefetchReader.Parse(Fixture(31,296,[@"C:\one\TOOL.EXE",@"E:\two\TOOL.EXE"]),mappings);
        Check(ambiguous.ProcessPath=="","Ambiguous executable must remain unknown");
        Invalid([77,65,77,4,255,255,255,127]);
        Check(EvidencePolicy.IsDefenderPlatform(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"),"Defender exclusion");
        Check(!EvidencePolicy.IsDefenderPlatform(@"C:\ProgramData\Microsoft\Windows Defender\Platform-evil\tool.exe"),"Defender sibling remains visible");
        Check(!EvidencePolicy.IsDefenderPlatform(@"C:\ProgramData\Microsoft\Windows Defender\Platform\..\evil.exe"),"Defender traversal remains visible");
        Console.WriteLine("PASS: Prefetch v17/23/26/30 (both layouts)/31, native MAM decompression, Unicode paths, run counts/times, malformed and ambiguous data, Defender boundaries");
    }
    static byte[] Compress(byte[] data)
    {
        Check(RtlGetCompressionWorkSpaceSize(4,out uint workSize,out _)==0,"Compression workspace");
        IntPtr work=Marshal.AllocHGlobal((int)workSize);
        try
        {
            var compressed=new byte[data.Length*2+4096];
            Check(RtlCompressBuffer(4,data,(uint)data.Length,compressed,(uint)compressed.Length,4096,out uint size,work)==0,"Compress fixture");
            var mam=new byte[size+8];mam[0]=77;mam[1]=65;mam[2]=77;mam[3]=4;
            BinaryPrimitives.WriteUInt32LittleEndian(mam.AsSpan(4),(uint)data.Length);
            Array.Copy(compressed,0,mam,8,size);return mam;
        }
        finally { Marshal.FreeHGlobal(work); }
    }
    [DllImport("ntdll.dll")] static extern int RtlGetCompressionWorkSpaceSize(ushort format,out uint workspace,out uint fragment);
    [DllImport("ntdll.dll")] static extern int RtlCompressBuffer(ushort format,byte[] input,uint inputSize,byte[] output,uint outputSize,uint chunk,out uint size,IntPtr workspace);
}
