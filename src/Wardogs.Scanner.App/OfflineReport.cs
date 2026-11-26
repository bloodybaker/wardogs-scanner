using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Wardogs.Scanner;

public sealed record OfflineReport(
    [property: JsonPropertyName("format")] string Format,
    [property: JsonPropertyName("format_version")] int FormatVersion,
    [property: JsonPropertyName("incident_id")] string IncidentId,
    [property: JsonPropertyName("report")] ScanReport Report)
{
    public static OfflineReport Create(string incidentId, ScanReport report) =>
        new("wardogs-offline-report", 1, incidentId, report);

    public async Task<string> SaveAsync(string folder)
    {
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, $"WARDOGS-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.json");
        var temporary = path + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await JsonSerializer.SerializeAsync(stream, this);
            File.Move(temporary, path);
            return path;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
