using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Wardogs.Scanner;

// Layout reference: libyal/libscca documentation/Windows Prefetch File (PF) format.
public static class PrefetchReader
{
    private const int MaxBytes = 16 * 1024 * 1024;
    public sealed record Entry(string Executable, string ProcessPath, uint RunCount, double[] RunTimes, uint Version);

    public static Entry Read(string path, IReadOnlyDictionary<string, string>? devicePaths = null)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (file.Length > MaxBytes) throw new InvalidDataException("Prefetch size limit");
        var bytes = new byte[(int)file.Length];
        file.ReadExactly(bytes);
        return Parse(bytes, devicePaths ?? DevicePaths());
    }

    public static Entry Parse(byte[] bytes, IReadOnlyDictionary<string, string>? devicePaths = null)
    {
        if (bytes.Length > MaxBytes) throw new InvalidDataException("Prefetch size limit");
        if (bytes.Length >= 8 && bytes[0] == 'M' && bytes[1] == 'A' && bytes[2] == 'M')
            bytes = Decompress(bytes);
        uint U32(int offset)
        {
            if (offset < 0 || offset > bytes.Length - 4) throw new InvalidDataException("Truncated Prefetch");
            return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        }
        string Utf16(uint offset, uint size)
        {
            if (size % 2 != 0 || offset > bytes.Length || size > bytes.Length - offset)
                throw new InvalidDataException("Invalid Prefetch string range");
            return Encoding.Unicode.GetString(bytes, (int)offset, (int)size);
        }
        if (bytes.Length < 152 || U32(4) != 0x41434353 || U32(12) != bytes.Length)
            throw new InvalidDataException("Invalid Prefetch header");
        uint version = U32(0), metrics = U32(84);
        if (metrics > bytes.Length) throw new InvalidDataException("Truncated Prefetch information");
        int countOffset = version switch
        {
            17 when metrics == 152 => 144,
            23 when metrics == 240 => 152,
            26 when metrics == 304 => 208,
            30 when metrics == 304 => 208,
            30 or 31 when metrics == 296 => 200,
            _ => throw new InvalidDataException("Unsupported Prefetch layout")
        };
        var executable = Utf16(16, 60).Split('\0')[0];
        if (executable.Length == 0) throw new InvalidDataException("Missing executable name");
        var times = new List<double>();
        int timeOffset = version == 17 ? 120 : 128;
        for (int i = 0; i < (version >= 26 ? 8 : 1); i++)
        {
            long raw = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(timeOffset + i * 8, 8));
            if (raw == 0) continue;
            try
            {
                var time = new DateTimeOffset(DateTime.FromFileTimeUtc(raw)).ToUnixTimeSeconds();
                if (time >= 946684800 && time <= DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds()) times.Add(time);
            }
            catch (ArgumentOutOfRangeException) { throw new InvalidDataException("Invalid Prefetch timestamp"); }
        }
        var candidates = Utf16(U32(100), U32(104)).Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => p.Contains('\\'))
            .Where(p => string.Equals(p[(p.LastIndexOf('\\') + 1)..], executable, StringComparison.OrdinalIgnoreCase)
                || (executable.Length == 29 && p[(p.LastIndexOf('\\') + 1)..].StartsWith(executable, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        // Never choose an arbitrary same-name executable from another directory.
        var mappings = new Dictionary<string, string>(devicePaths ?? DevicePaths(), StringComparer.OrdinalIgnoreCase);
        uint volumes = U32(108), volumeCount = U32(112), volumeSize = U32(116);
        uint entrySize = version == 17 ? 40u : version < 30 ? 104u : 96u;
        if (volumes > bytes.Length || volumeSize > bytes.Length - volumes || volumeCount > volumeSize / entrySize)
            throw new InvalidDataException("Invalid Prefetch volumes");
        for (uint i = 0; i < volumeCount; i++)
        {
            int entry = checked((int)(volumes + i * entrySize));
            uint nameOffset = U32(entry), nameChars = U32(entry + 4);
            if (nameOffset > volumeSize || nameChars > (volumeSize - nameOffset) / 2)
                throw new InvalidDataException("Invalid Prefetch volume name");
            var name = Utf16(volumes + nameOffset, nameChars * 2).TrimEnd('\0');
            if (mappings.TryGetValue("serial:" + U32(entry + 16).ToString("X8"), out var drive)) mappings.TryAdd(name, drive);
        }
        string processPath = candidates.Length == 1 ? ResolvePath(candidates[0], mappings) : "";
        if (candidates.Length == 1) executable = candidates[0][(candidates[0].LastIndexOf('\\') + 1)..];
        return new(executable, processPath, U32(countOffset), times.Distinct().OrderDescending().ToArray(), version);
    }

    public static string ResolvePath(string path, IReadOnlyDictionary<string, string>? mappings = null)
    {
        foreach (var pair in mappings ?? DevicePaths())
            if (path.StartsWith(pair.Key + "\\", StringComparison.OrdinalIgnoreCase))
                return pair.Value.TrimEnd('\\') + path[pair.Key.Length..];
        return path; // Preserve a native volume path when its drive is no longer mounted.
    }

    public static Dictionary<string, string> DevicePaths()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string drive in Environment.GetLogicalDrives())
        {
            var buffer = new StringBuilder(1024);
            if (QueryDosDevice(drive[..2], buffer, buffer.Capacity) != 0) result.TryAdd(buffer.ToString(), drive[..2]);
            if (GetVolumeInformation(drive, null, 0, out uint serial, out _, out _, null, 0))
                result.TryAdd("serial:" + serial.ToString("X8"), drive[..2]);
        }
        return result;
    }

    private static byte[] Decompress(byte[] bytes)
    {
        if (bytes[3] != 4 && bytes[3] != 0x84) throw new InvalidDataException("Unsupported Prefetch compression");
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4));
        if (size < 152 || size > MaxBytes) throw new InvalidDataException("Invalid Prefetch decompressed size");
        int offset = bytes[3] == 0x84 ? 12 : 8;
        if (bytes.Length <= offset) throw new InvalidDataException("Truncated MAM header");
        if (RtlGetCompressionWorkSpaceSize(4, out _, out uint workspaceSize) != 0 || workspaceSize > MaxBytes)
            throw new InvalidDataException("Prefetch decompressor unavailable");
        var workspace = Marshal.AllocHGlobal((int)workspaceSize);
        try
        {
            var output = new byte[size];
            var input = bytes[offset..];
            if (RtlDecompressBufferEx(4, output, size, input, (uint)input.Length, out uint actual, workspace) != 0 || actual != size)
                throw new InvalidDataException("Invalid compressed Prefetch");
            return output;
        }
        finally { Marshal.FreeHGlobal(workspace); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string name, StringBuilder target, int length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(string root, StringBuilder? name, int nameSize, out uint serial, out uint maxComponent, out uint flags, StringBuilder? filesystem, int filesystemSize);
    [DllImport("ntdll.dll")]
    private static extern int RtlGetCompressionWorkSpaceSize(ushort format, out uint buffer, out uint fragment);
    [DllImport("ntdll.dll")]
    private static extern int RtlDecompressBufferEx(ushort format, byte[] output, uint outputSize, byte[] input, uint inputSize, out uint finalSize, IntPtr workspace);
}
