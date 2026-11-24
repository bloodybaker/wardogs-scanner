using System.IO;

namespace Wardogs.Scanner;

public static class EvidencePolicy
{
    public static bool IsSystem32(string path)
    {
        path = Environment.ExpandEnvironmentVariables(path).Replace('/', '\\');
        return path.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsDefenderPlatform(string path)
    {
        path = Environment.ExpandEnvironmentVariables(path).Replace('/', '\\').Trim('"');
        if (path.StartsWith(@"\??\") || path.StartsWith(@"\\?\")) path = path[4..];
        try { path = Path.GetFullPath(path); } catch { return false; }
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
        return path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
    }

    public static Evidence Normalize(Evidence item) => IsDefenderPlatform(item.Path) && item.Severity != "none"
        ? item with { Severity = "none", Confidence = "unknown", Explanation = "Компонент Windows Defender Platform. Виключено із сигналів ризику за каталогом.",
            Details = new(item.Details) { ["risk_exclusion"] = "windows_defender_platform" } }
        : item;
}
