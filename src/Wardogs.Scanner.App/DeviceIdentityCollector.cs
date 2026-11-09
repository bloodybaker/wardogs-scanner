using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Wardogs.Scanner;

public static class DeviceIdentityCollector
{
    public static DeviceIdentity? Collect()
    {
        try {
            var size=GetSystemFirmwareTable(0x52534D42,0,null,0);
            if(size is >=8 and <=4_000_000) {
                var buffer=new byte[size];
                var read=GetSystemFirmwareTable(0x52534D42,0,buffer,size);
                if(read==size && FromSmbios(buffer) is { } identity) return identity;
            }
        } catch(Exception ex) when(ex is System.ComponentModel.Win32Exception or EntryPointNotFoundException) { }
        try {
            using var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography",false);
            if(Guid.TryParse(Convert.ToString(key?.GetValue("MachineGuid")),out var guid) && guid!=Guid.Empty)
                return Hash("windows_installation_v1",guid.ToString("D"));
        } catch(Exception ex) when(ex is UnauthorizedAccessException or System.Security.SecurityException or System.IO.IOException) { }
        return null;
    }

    public static DeviceIdentity? FromSmbios(ReadOnlySpan<byte> raw)
    {
        if(raw.Length<8) return null;
        var length=BitConverter.ToUInt32(raw[4..]);
        if(length>raw.Length-8) return null;
        var data=raw.Slice(8,(int)length);int offset=0;
        while(offset+4<=data.Length) {
            var size=data[offset+1];
            if(size<4 || offset+size>data.Length) return null;
            if(data[offset]==1 && size>=24) {
                var uuid=data.Slice(offset+8,16).ToArray();
                if(uuid.All(b=>b==0) || uuid.All(b=>b==255)) return null;
                return Hash("smbios_uuid_v1",Convert.ToHexString(uuid));
            }
            if(data[offset]==127) break;
            offset+=size;
            while(offset+1<data.Length && (data[offset]!=0 || data[offset+1]!=0)) offset++;
            offset+=2;
        }
        return null;
    }
    private static DeviceIdentity Hash(string kind,string value) => new(kind,
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("wardogs.com.ua/scanner/device/v1\0"+kind+"\0"+value))).ToLowerInvariant());
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern uint GetSystemFirmwareTable(uint provider,uint table,[Out] byte[]? buffer,uint size);
}
