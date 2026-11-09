using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Wardogs.Scanner;

public static class BrowserJournalCollector
{
    public sealed record Trace(ulong Parent, string Name, long Usn, double Time, uint Reason);
    public sealed record Result(List<Trace> Traces, string Coverage);
    public static ulong? DirectoryId(string folder)
    {
        using var handle=CreateFile(folder,0,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);
        var info=new byte[52];
        return !handle.IsInvalid && GetFileInformationByHandle(handle,info)
            ? ((ulong)BitConverter.ToUInt32(info,44)<<32)|BitConverter.ToUInt32(info,48) : null;
    }

    public static Result Read(string root, CancellationToken token)
    {
        using var handle=CreateFile($@"\\.\{root.TrimEnd('\\')}",0x80000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
        var journal=new byte[128];
        if (handle.IsInvalid || !Query(handle,0x900f4,IntPtr.Zero,0,journal,journal.Length,out var size,IntPtr.Zero) || size<56)
            return new([],"unavailable");
        var end=BitConverter.ToInt64(journal,16);
        var request=new ReadData{Start=Math.Max(BitConverter.ToInt64(journal,8),end-64L*1024*1024),Mask=0x204,Journal=BitConverter.ToUInt64(journal,0)};
        var result=new List<Trace>();var buffer=new byte[256*1024];int batches=0;
        var timer=System.Diagnostics.Stopwatch.StartNew();
        while (request.Start<end && batches++<512 && timer.Elapsed.TotalSeconds<8)
        {
            token.ThrowIfCancellationRequested();
            if (!ReadJournal(handle,0x900bb,ref request,Marshal.SizeOf<ReadData>(),buffer,buffer.Length,out var returned,IntPtr.Zero) || returned<8)
                return new(result,"partial");
            result.AddRange(Parse(buffer.AsSpan(8,returned-8)));
            var next=BitConverter.ToInt64(buffer,0);
            if (next<=request.Start) break;
            request.Start=next;
        }
        return new(result,request.Start>=end?"bounded_recent_window":"partial");
    }

    public static List<Trace> Parse(ReadOnlySpan<byte> records)
    {
        var result=new List<Trace>();
        int offset=0;
        while (offset+60<=records.Length)
        {
            var record=records[offset..];int size=BitConverter.ToInt32(record);
            if (size<60 || size>record.Length) break;
            if (BitConverter.ToUInt16(record[4..])==2)
            {
                var reason=BitConverter.ToUInt32(record[40..]);
                var length=BitConverter.ToUInt16(record[56..]);var nameOffset=BitConverter.ToUInt16(record[58..]);
                if ((reason&0x204)!=0 && length%2==0 && nameOffset>=60 && nameOffset+length<=size)
                {
                    var name=Encoding.Unicode.GetString(record.Slice(nameOffset,length));
                    if (name.Equals("History",StringComparison.OrdinalIgnoreCase)||name.Equals("places.sqlite",StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            var time=DateTimeOffset.FromFileTime(BitConverter.ToInt64(record[32..])).ToUnixTimeMilliseconds()/1000d;
                            result.Add(new(BitConverter.ToUInt64(record[16..]),name,BitConverter.ToInt64(record[24..]),time,reason));
                        }
                        catch (ArgumentOutOfRangeException) { }
                    }
                }
            }
            offset+=size;
        }
        return result;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ReadData { public long Start; public uint Mask,Close; public ulong Timeout,Wait,Journal; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file,[Out] byte[] information);
    [DllImport("kernel32.dll",EntryPoint="DeviceIoControl",SetLastError=true)] private static extern bool Query(SafeFileHandle file,uint code,IntPtr input,int inputSize,byte[] output,int outputSize,out int returned,IntPtr overlapped);
    [DllImport("kernel32.dll",EntryPoint="DeviceIoControl",SetLastError=true)] private static extern bool ReadJournal(SafeFileHandle file,uint code,ref ReadData input,int inputSize,byte[] output,int outputSize,out int returned,IntPtr overlapped);
}
