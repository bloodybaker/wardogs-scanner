namespace Wardogs.Scanner;

public static class EvidencePrioritizer
{
    private static readonly Dictionary<string, int> InventoryLimits = new(StringComparer.OrdinalIgnoreCase)
    {
        ["running_process"] = 80,
        ["recent_executable"] = 80,
        ["prefetch_metadata"] = 110,
        ["pca_execution"] = 75,
        ["bam_execution"] = 75,
        ["autorun"] = 55,
        ["startup_item"] = 30,
        ["security_posture"] = 12,
        ["journal_status"] = 5,
    };

    public static List<Evidence> Select(IEnumerable<Evidence> source, int limit = 500)
    {
        var all = source.ToList();
        var priority = all.Where(item => !string.Equals(item.Severity, "none", StringComparison.OrdinalIgnoreCase))
            .OrderBy(item => SeverityRank(item.Severity)).ThenByDescending(item => item.Timestamp ?? 0).Take(limit).ToList();
        if (priority.Count == limit) return priority;

        foreach (var group in all.Where(item => string.Equals(item.Severity, "none", StringComparison.OrdinalIgnoreCase))
                     .GroupBy(item => item.Type, StringComparer.OrdinalIgnoreCase)
                     .OrderBy(group => InventoryOrder(group.Key)))
        {
            var groupLimit = InventoryLimits.GetValueOrDefault(group.Key, 40);
            priority.AddRange(group.OrderByDescending(item => item.Timestamp ?? 0).Take(Math.Min(groupLimit, limit - priority.Count)));
            if (priority.Count == limit) break;
        }
        return priority;
    }

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4,
    };

    private static int InventoryOrder(string type) => type.ToLowerInvariant() switch
    {
        "browser_history_clear_artifact" => -3, "browser_history_status" => -2, "dma_scan_coverage" => -1, "security_posture" => 0, "journal_status" => 1, "running_process" => 2,
        "recent_executable" => 3, "autorun" => 4, "startup_item" => 5,
        "bam_execution" => 6, "pca_execution" => 7, "prefetch_metadata" => 8, _ => 9,
    };
}
