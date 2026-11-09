using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Wardogs.Scanner;

public static class BrowserIndicators
{
    public const string CatalogVersion = "2026-11-04.1";
    private static readonly string[] Terms = ["aimbot", "wallhack", "triggerbot", "silent aim", "no recoil", "radarhack", "dma", "esp", "cheat", "cheats", "чит", "читы", "чити", "чіт", "чіти", "вх", "аимбот", "аімбот"];

    public static string[] MatchKeywords(string url)
    {
        if (url.Length > 16000 || !Uri.TryCreate(url,UriKind.Absolute,out var uri) || uri.Scheme is not ("https" or "http")) return [];
        // Never flag official/community privacy, support or anti-cheat pages by keywords.
        if (new[] { "wardogs.com.ua", "wardogs.today", "wardogs.com", "steampowered.com", "steamcommunity.com", "faceit.com", "microsoft.com" }
            .Any(host=>uri.Host.Equals(host,StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith("."+host,StringComparison.OrdinalIgnoreCase))) return [];
        string text;
        try { text=Uri.UnescapeDataString(uri.PathAndQuery).Replace('+',' ').Replace('-',' ').Replace('_',' ').ToLowerInvariant(); }
        catch (UriFormatException) { return []; }
        if (!Regex.IsMatch(text,@"\b(?:war\s*dogs|вар\s*догс|вардог|вардоги)\b",RegexOptions.CultureInvariant)) return [];
        if (Regex.IsMatch(text,@"\b(anti\s*cheat|report\s+cheat|report\s+cheaters|античит|антічит)\b",RegexOptions.CultureInvariant)) return [];
        return Terms.Concat(new[]{"hack", "hacks", "hacking", "external", "external cheat", "recoil", "norecoil", "wall hack", "aim bot", "trigger bot", "esp hack", "макрос", "макроси", "макросы", "macro", "macros", "хак", "хаки", "радар", "софт", "читер", "читов", "чітів"})
            .Where(term=>Regex.IsMatch(text,@"(?<![\p{L}\p{N}])"+Regex.Escape(term)+@"(?![\p{L}\p{N}])",RegexOptions.CultureInvariant)).Distinct().Take(8).ToArray();
    }

    public static string ReportUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return "";
        // Preserve matched resource/search URLs, but never credentials, fragments
        // or incidental authentication/session parameters from the browser.
        var safe = new UriBuilder(uri) { UserName = "", Password = "", Fragment = "" };
        safe.Query = string.Join("&", uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Where(part => new[]{"q","query","search","search_query","text","p","v","id"}
                .Contains(Uri.UnescapeDataString(part.Split('=')[0]).ToLowerInvariant())));
        var value = safe.Uri.AbsoluteUri;
        return value.Length <= 2048 ? value : value[..2048];
    }

    public static double? ChromiumTimestamp(string? value)
    {
        if (!long.TryParse(value,NumberStyles.Integer,CultureInfo.InvariantCulture,out var ticks) || ticks<=0) return null;
        try
        {
            var unix=DateTimeOffset.FromFileTime(checked(ticks*10)).ToUnixTimeMilliseconds()/1000d;
            return unix>=946684800 && unix<=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+300 ? unix : null;
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException) { return null; }
    }

    public static List<(string Rule, string Explanation, double? Time, Dictionary<string,object?> Details)> AnalyzePreferences(string text,bool firefox)
    {
        var items=new List<(string,string,double?,Dictionary<string,object?>)>();
        if (firefox)
        {
            bool enabled=Regex.IsMatch(text,"user_pref\\(\\s*\"privacy\\.sanitize\\.sanitizeOnShutdown\"\\s*,\\s*true\\s*\\)");
            bool history=Regex.IsMatch(text,"user_pref\\(\\s*\"privacy\\.clearOnShutdown(?:_v2)?\\.(?:history|historyFormDataAndDownloads|browsingHistoryAndDownloads)\"\\s*,\\s*true\\s*\\)");
            if (enabled && history) items.Add(("WD-BROWSER-CLEAR-POLICY","У Firefox налаштовано видалення історії при закритті. Це політика браузера, а не доказ очищення в конкретний час.",null,new(){["artifact"]="prefs.js",["clear_on_exit"]=true,["clear_time"]="not_available"}));
            return items;
        }
        using var doc=JsonDocument.Parse(text);
        if (!doc.RootElement.TryGetProperty("browser",out var browser) || browser.ValueKind!=JsonValueKind.Object) return items;
        if (browser.TryGetProperty("last_clear_browsing_data_time",out var stamp))
        {
            var time=ChromiumTimestamp(stamp.ValueKind==JsonValueKind.String?stamp.GetString():stamp.ToString());
            if (time.HasValue) items.Add(("WD-BROWSER-CLEAR-MARKER","У Preferences збережено час останньої операції очищення даних браузера. Маркер не визначає, чи очищали саме історію, кеш або cookies; обсяг видалення невідомий.",time,new(){["artifact"]="browser.last_clear_browsing_data_time",["clear_time"]=time,["history_cleared"]="not_determined",["scope"]="browsing_data_operation"}));
        }
        return items;
    }
}
