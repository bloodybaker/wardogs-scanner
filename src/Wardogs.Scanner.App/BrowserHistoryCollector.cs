using Microsoft.Data.Sqlite;
using System.IO;

namespace Wardogs.Scanner;

public static class BrowserHistoryCollector
{
    private sealed record Rule(string Id, string Host, string PathNeedle, string Label);
    private sealed record Profile(string Browser, string Name, string Database, bool Firefox);
    private sealed record Visit(string Url, long Count, long? First, long? Last);

    private static readonly Rule[] Rules = [
        new("WD-WEB-DIVINE", "divinedigital.cc", "/products/wardogs-software", "User-supplied WARDOGS resource"),
        new("WD-WEB-DIVINE-INVITE", "discord.com", "/invite/divineud", "User-supplied invite"),
        new("WD-WEB-DIVINE-SHORT", "discord.gg", "/divineud", "User-supplied invite"),
        new("WD-WEB-PRIVATECHEATZ", "privatecheatz.com", "/wardogs-hacks", "User-supplied WARDOGS resource"),
        new("WD-WEB-DUCKS", "ducks-services.com", "/store/category/186-wardogs", "WARDOGS resource"),
        new("WD-WEB-CHEATSTORE", "cheatstore.net", "", "User-supplied resource; game not established"),
        new("WD-WEB-BURGER", "burgercheats.com", "", "User-supplied resource; game not established"),
        new("WD-WEB-SHXDOW", "shxdowcheats.net", "", "User-supplied resource; game not established"),
        new("WD-WEB-GHOST", "ghost.one", "", "User-supplied resource; game not established"),
        new("WD-WEB-HACKSTORE", "hack-store.ru", "", "User-supplied resource; game not established"),
        new("WD-WEB-CHEATSFORWARDOGS", "cheatsforwardogs.net", "", "User-supplied WARDOGS resource"),
        new("WD-WEB-SYNTHETIC", "syntheticskill.com", "", "User-supplied resource; game not established"),
        new("WD-WEB-SURCH", "surchcheats.com", "", "User-supplied resource; game not established"),
        new("WD-WEB-ZSOFT", "zsoft.store", "", "User-supplied resource; game not established"),
        new("WD-WEB-BADBOY", "badboycheats.com", "", "User-supplied resource; game not established"),
        new("WD-WEB-VIDEO", "youtube.com", "v=peXKyGX5n3s", "User-supplied video"),
        new("WD-WEB-VIDEO-SHORT", "youtu.be", "/peXKyGX5n3s", "User-supplied video"),
        new("WD-WEB-ELITEPVPERS", "elitepvpers.com", "/forum/wardogs", "WARDOGS marketplace/forum"),
        new("WD-WEB-FORGECHEATS", "forgecheats.com", "/game/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-CHEATSDOTCO", "cheats.co", "/game/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-GETCHEATS", "getcheats.io", "/game/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-WARDOGSCHEATNET", "wardogscheat.net", "", "WARDOGS cheat storefront"),
        new("WD-WEB-IVSOFTE", "ivsofte.biz", "/status/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-MADCHAD", "madchad.net", "/product/madtech-wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-WARDOGCHEATS", "wardogcheats.com", "", "WARDOGS cheat storefront"),
        new("WD-WEB-SATANO", "wh-satano.ru", "/cheats/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-BATTLELOG", "battlelog.co", "/wardogs-hacks", "WARDOGS cheat storefront"),
        new("WD-WEB-LAVICHEATS", "lavicheats.com", "/wardogs-hacks", "WARDOGS cheat storefront"),
        new("WD-WEB-DISCONNECT", "disconnectcheats.com", "/store/category/5-wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-KERNAIM", "kernaim.to", "/cheats/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-UNKNOWNCHEATS-FILE", "unknowncheats.me", "id=55897", "WARDOGS-linked download page"),
        new("WD-WEB-WARDOGSESP", "wardogsesp.com", "", "WARDOGS cheat storefront"),
        new("WD-WEB-WARDOGSHACKS", "wardogshacks.com", "", "WARDOGS cheat storefront"),
        new("WD-WEB-WARDOGSCHEATSCO", "wardogscheats.co", "", "WARDOGS cheat storefront"),
        new("WD-WEB-WARDOGSHACK", "wardogshack.com", "", "WARDOGS cheat storefront"),
        new("WD-WEB-PHANTOMDMA", "phantomdma.cc", "/products/wardogs", "WARDOGS DMA storefront"),
        new("WD-WEB-ANCHORCHEATS", "anchorcheats.com", "/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-UNNAMEDTECH", "unnamedtech.cc", "/catalog/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-BETTERCHEATS", "bettercheats.mysellauth.com", "/products/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-BETTERCHEATS-PRODUCT", "bettercheats.mysellauth.com", "/product/wardogs-cheat", "WARDOGS cheat product"),
        new("WD-WEB-BETTERCHEATS-LEGACY", "bettercheats.com", "/products/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-BUYWARDOGS", "buywardogscheat.org", "", "WARDOGS cheat storefront"),
        new("WD-WEB-CHEATFORWARDOGSORG", "cheatforwardogs.org", "", "WARDOGS cheat storefront"),
        new("WD-WEB-CHEATFORWARDOGSNET", "cheatforwardogs.net", "", "WARDOGS cheat storefront"),
        new("WD-WEB-WARDOGSCHEATSPC", "wardogscheatspc.com", "", "WARDOGS cheat storefront"),
        new("WD-WEB-NOWAX", "nowaxcheats.com", "/store/wardogs", "WARDOGS cheat storefront"),
        new("WD-WEB-PHANTOMCATALOG", "phantomdma.cc", "/products", "WARDOGS/Rust DMA storefront"),
        new("WD-WEB-1BWSHOP", "1bwshop.com", "/wardogs", "WARDOGS cheat storefront"),
    ];

    public static Task<(ModuleResult Module, List<Evidence> Evidence, List<string> Errors)> CollectAsync(CancellationToken token) =>
        Task.Run(() => Collect(token), token);

    private static (ModuleResult, List<Evidence>, List<string>) Collect(CancellationToken token)
    {
        var started = Now();
        var evidence = new List<Evidence>();
        var errors = new List<string>();
        var checkedCount = 0;
        var failed = 0;
        var journals = new Dictionary<string,BrowserJournalCollector.Result>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in DiscoverProfiles().Take(40))
        {
            token.ThrowIfCancellationRequested();
            checkedCount++;
            try
            {
                var root=Path.GetPathRoot(profile.Database)!;
                if (!journals.TryGetValue(root,out var journal)) journals[root]=journal=BrowserJournalCollector.Read(root,token);
                var parent=BrowserJournalCollector.DirectoryId(Path.GetDirectoryName(profile.Database)!);
                var traces=journal.Traces.Where(t=>parent.HasValue && t.Parent==parent.Value && t.Name.Equals(Path.GetFileName(profile.Database),StringComparison.OrdinalIgnoreCase))
                    .GroupBy(t=>(t.Name,t.Time,t.Reason)).Select(g=>g.First()).OrderByDescending(t=>t.Time).Take(10);
                foreach (var trace in traces)
                    evidence.Add(Item("browser-usn-"+trace.Usn,"browser_history_file_event",profile,trace.Time,"WD-BROWSER-HISTORY-USN","low","high",
                        (trace.Reason&0x200)!=0 ? "NTFS зафіксувала видалення history-файла саме в цьому профілі. Час події відомий; хто і навіщо видалив файл — невідомо. Можливе обслуговування браузера."
                        : "NTFS зафіксувала скорочення history-файла цього профілю. Це може бути очищення або звичайне SQLite-обслуговування; видалення конкретних записів не доведено.",
                        new(){["artifact"]=trace.Name,["operation"]=(trace.Reason&0x200)!=0?"file_deleted":"file_truncated",["clear_time"]=trace.Time,["journal_coverage"]=journal.Coverage,["cheating_proof"]=false}));
                evidence.Add(Item("browser-journal","browser_history_status",profile,null,"WD-BROWSER-JOURNAL-COVERAGE","none","unknown",
                    "Перевірка NTFS обмежена останнім доступним вікном журналу. Відсутність події не виключає очищення записів усередині SQLite або видалення старішої історії.",
                    new(){["journal_coverage"]=parent.HasValue?journal.Coverage:"unavailable",["window_max_bytes"]=64*1024*1024}));
                var profileEvidence = AnalyzeProfile(profile.Database, profile.Firefox, profile.Browser, profile.Name);
                evidence.AddRange(profileEvidence);
                if (!File.Exists(profile.Database) || profileEvidence.Any(e => e.RuleId == "WD-BROWSER-HISTORY-LIMIT")) failed++;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or SqliteException or System.Text.Json.JsonException)
            {
                failed++;
                errors.Add($"browser_history.{profile.Browser}: {ex.GetType().Name}");
            }
        }
        var status = checkedCount > 0 && failed < checkedCount ? (failed == 0 ? "success" : "partial") : "partial";
        var error = checkedCount == 0 ? "Підтримувані браузерні профілі не знайдено." : failed > 0 ? "Частина браузерних профілів недоступна." : "";
        return (new ModuleResult("browser_history", status, started, Now(), checkedCount, error), evidence, errors);
    }

    public static List<Evidence> AnalyzeProfile(string database, bool firefox, string browser = "Fixture", string name = "Default")
    {
        var profile=new Profile(browser,name,database,firefox);
        var result=new List<Evidence>();
        var folder=Path.GetDirectoryName(database)!;
        var prefs=Path.Combine(folder,firefox?"prefs.js":"Preferences");
        if (File.Exists(prefs))
        {
            try
            {
                using var input=new FileStream(prefs,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
                if (input.Length>16_000_000) throw new IOException("Preferences size limit");
                using var reader=new StreamReader(input);
                foreach (var marker in BrowserIndicators.AnalyzePreferences(reader.ReadToEnd(),firefox))
                    result.Add(Item("browser-clear-"+StableId(browser+name+marker.Rule),"browser_history_clear_artifact",profile,marker.Time,
                        marker.Rule,"none","high",marker.Explanation,marker.Details));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
            {
                result.Add(Item("browser-prefs-"+StableId(browser+name),"browser_history_status",profile,null,"WD-BROWSER-PREFS-UNAVAILABLE","none","unknown",
                    "Маркери очищення в налаштуваннях браузера недоступні. Відсутність маркера не виключає очищення.",new(){["artifact"]=Path.GetFileName(prefs),["availability"]="unavailable"}));
            }
        }
        result.AddRange(FindReplacementArtifacts(profile));
        if (!File.Exists(database))
        {
            result.Add(Item("browser-missing-"+StableId(browser+name),"browser_history_status",profile,null,"WD-BROWSER-HISTORY-MISSING","none","unknown",
                "Профіль існує, але history-база відсутня. Можливі новий профіль, приватний режим або видалення; встановити причину чи час неможливо.",new(){["history_available"]=false,["clear_time"]="not_available"}));
            return result;
        }
        using var snapshot=DatabaseSnapshot.Create(database);
        using var connection=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=snapshot.Database,Mode=SqliteOpenMode.ReadOnly,Cache=SqliteCacheMode.Private,Pooling=false}.ToString());
        connection.Open();
        using (var check=connection.CreateCommand())
        {
            check.CommandText="PRAGMA quick_check(1)";
            if (!string.Equals(Convert.ToString(check.ExecuteScalar()),"ok",StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("History snapshot consistency check failed");
        }
        var stats=ReadStats(connection,firefox);
        result.Add(StatusEvidence(profile,stats,database));
        var visits=ReadMatches(connection,firefox).ToList();
        if (visits.Count>50000)
        {
            visits.RemoveAt(50000);
            result.Add(Item("browser-limit-"+StableId(browser+name),"browser_history_status",profile,null,
                "WD-BROWSER-HISTORY-LIMIT","none","unknown",
                "????????? ?????? ?????? ???????. ???????? ????????; ????? ????????? ?????????????.",
                new(){["coverage"]="partial",["limit"]=50000}));
        }
        foreach (var hit in visits.Select(v=>(Visit:v,Rule:MatchRule(v.Url))).Where(x=>x.Rule!=null))
        {
            result.Add(MatchEvidence(profile,hit.Rule!,hit.Visit));
        }
        var keywordHits=visits.Where(v=>MatchRule(v.Url)==null).Select(v=>(Visit:v,Terms:BrowserIndicators.MatchKeywords(v.Url))).Where(x=>x.Terms.Length>0).ToList();
        foreach (var hit in keywordHits)
        {
            var terms=string.Join(", ",hit.Terms);
            result.Add(Item("browser-keywords-"+StableId(browser+name+hit.Visit.Url+hit.Visit.Last),"browser_keyword_match",profile,ConvertTime(hit.Visit.Last,firefox),
                "WD-BROWSER-WARDOGS-KEYWORDS","low","low",
                "У локальних URL знайдено назву WARDOGS разом із ключовими словами про чити/DMA. Це може бути пошук, новина або дослідження; не є доказом завантаження чи використання.",
                new(){["keywords"]=terms,["matched_url"]=BrowserIndicators.ReportUrl(hit.Visit.Url),["first_visit"]=ConvertTime(hit.Visit.First,firefox),["last_visit"]=ConvertTime(hit.Visit.Last,firefox),["visits"]=hit.Visit.Count,["catalog_version"]=BrowserIndicators.CatalogVersion,["cheating_proof"]=false}));
        }
        return result;
    }

    private static string[] SafeDirectories(string root)
    {
        try { return Directory.GetDirectories(root); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static IEnumerable<Profile> DiscoverProfiles()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var chromiumRoots = new[] {
            ("Google Chrome", Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Google Chrome Beta", Path.Combine(local, "Google", "Chrome Beta", "User Data")),
            ("Google Chrome Dev", Path.Combine(local, "Google", "Chrome Dev", "User Data")),
            ("Google Chrome Canary", Path.Combine(local, "Google", "Chrome SxS", "User Data")),
            ("Microsoft Edge", Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Microsoft Edge Beta", Path.Combine(local, "Microsoft", "Edge Beta", "User Data")),
            ("Microsoft Edge Dev", Path.Combine(local, "Microsoft", "Edge Dev", "User Data")),
            ("Microsoft Edge Canary", Path.Combine(local, "Microsoft", "Edge SxS", "User Data")),
            ("Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Brave Beta", Path.Combine(local, "BraveSoftware", "Brave-Browser-Beta", "User Data")),
            ("Brave Nightly", Path.Combine(local, "BraveSoftware", "Brave-Browser-Nightly", "User Data")),
            ("Vivaldi", Path.Combine(local, "Vivaldi", "User Data")),
            ("Chromium", Path.Combine(local, "Chromium", "User Data")),
            ("Yandex Browser", Path.Combine(local, "Yandex", "YandexBrowser", "User Data")),
            ("Arc", Path.Combine(local, "The Browser Company", "Arc", "User Data")),
            ("Epic Privacy Browser", Path.Combine(local, "Epic Privacy Browser", "User Data")),
            ("Avast Secure Browser", Path.Combine(local, "AVAST Software", "Browser", "User Data")),
            ("AVG Secure Browser", Path.Combine(local, "AVG", "Browser", "User Data")),
            ("Comodo Dragon", Path.Combine(local, "Comodo", "Dragon", "User Data")),
            ("Cent Browser", Path.Combine(local, "CentBrowser", "User Data")),
            ("Slimjet", Path.Combine(local, "Slimjet", "User Data")),
            ("Thorium", Path.Combine(local, "Thorium", "User Data")),
        };
        foreach (var (browser, root) in chromiumRoots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var folder in SafeDirectories(root).Where(path => Path.GetFileName(path) == "Default" || Path.GetFileName(path).StartsWith("Profile ", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(path) == "Guest Profile"))
            {
                var database = Path.Combine(folder, "History");
                if (File.Exists(database) || File.Exists(Path.Combine(folder,"Preferences"))) yield return new(browser, Path.GetFileName(folder), database, false);
            }
        }
        foreach (var (browser, folder) in new[] {
            ("Opera", Path.Combine(roaming, "Opera Software", "Opera Stable")),
            ("Opera GX", Path.Combine(roaming, "Opera Software", "Opera GX Stable")),
        })
        {
            foreach (var database in OperaHistoryPaths(folder))
                yield return new(browser, Path.GetRelativePath(folder,Path.GetDirectoryName(database)!), database, false);
        }
        var geckoRoots = new[] {
            ("Mozilla Firefox", Path.Combine(roaming, "Mozilla", "Firefox", "Profiles")),
            ("Firefox Developer Edition", Path.Combine(roaming, "Mozilla", "Firefox", "Profiles")),
            ("LibreWolf", Path.Combine(roaming, "librewolf", "Profiles")),
            ("Waterfox", Path.Combine(roaming, "Waterfox", "Profiles")),
            ("Floorp", Path.Combine(roaming, "Floorp", "Profiles")),
            ("Zen Browser", Path.Combine(roaming, "zen", "Profiles")),
            ("Pale Moon", Path.Combine(roaming, "Moonchild Productions", "Pale Moon", "Profiles")),
        };
        var seenDatabases = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (browser, root) in geckoRoots)
            if (Directory.Exists(root))
            foreach (var folder in SafeDirectories(root))
            {
                var database = Path.Combine(folder, "places.sqlite");
                if ((File.Exists(database) || File.Exists(Path.Combine(folder,"prefs.js"))) && seenDatabases.Add(database)) yield return new(browser, SafeFirefoxProfile(Path.GetFileName(folder)), database, true);
            }
    }

    public static IEnumerable<string> OperaHistoryPaths(string root)
    {
        if (!Directory.Exists(root)) yield break;
        var pending = new Queue<(string Path,int Depth)>();
        pending.Enqueue((root,0));
        var checkedCount=0;
        while(pending.Count>0 && checkedCount++<200)
        {
            var (folder,depth)=pending.Dequeue();
            if ((File.GetAttributes(folder)&FileAttributes.ReparsePoint)!=0) continue;
            var database=Path.Combine(folder,"History");
            if(File.Exists(database)||File.Exists(Path.Combine(folder,"Preferences"))) yield return database;
            if(depth>=3) continue;
            foreach(var child in SafeDirectories(folder).Where(p=>!new[]{"Cache","Code Cache","GPUCache","ShaderCache","Service Worker"}.Contains(Path.GetFileName(p))))
                pending.Enqueue((child,depth+1));
        }
    }

    private static (long Count, long? First, long? Last) ReadStats(SqliteConnection connection, bool firefox)
    {
        using var command = connection.CreateCommand();
        command.CommandText = firefox
            ? "SELECT COUNT(*), MIN(visit_date), MAX(visit_date) FROM moz_historyvisits"
            : "SELECT COUNT(*), MIN(visit_time), MAX(visit_time) FROM visits";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return (0, null, null);
        return (reader.GetInt64(0), reader.IsDBNull(1) ? null : reader.GetInt64(1), reader.IsDBNull(2) ? null : reader.GetInt64(2));
    }

    private static IEnumerable<Visit> ReadMatches(SqliteConnection connection, bool firefox)
    {
        using var command = connection.CreateCommand();
        // Apply exact local matching before the limit: ordinary YouTube/Discord URLs
        // must never exhaust the candidate budget.
        connection.CreateFunction<string,int>("wd_match", url => MatchRule(url)!=null || BrowserIndicators.MatchKeywords(url).Length>0 ? 1 : 0);
        command.CommandText = firefox
            ? $"SELECT p.url, p.visit_count, MIN(v.visit_date), MAX(v.visit_date) FROM moz_places p LEFT JOIN moz_historyvisits v ON v.place_id=p.id WHERE wd_match(p.url)=1 GROUP BY p.id, p.url, p.visit_count LIMIT 50001"
            : $"SELECT p.url, p.visit_count, MIN(v.visit_time), MAX(v.visit_time) FROM urls p LEFT JOIN visits v ON v.url=p.id WHERE wd_match(p.url)=1 GROUP BY p.id, p.url, p.visit_count LIMIT 50001";
        using var reader = command.ExecuteReader();
        while (reader.Read())
            yield return new(reader.GetString(0), reader.GetInt64(1), reader.IsDBNull(2) ? null : reader.GetInt64(2), reader.IsDBNull(3) ? null : reader.GetInt64(3));
    }

    private static Evidence StatusEvidence(Profile profile, (long Count, long? First, long? Last) stats, string database)
    {
        var info = new FileInfo(database);
        var first = ConvertTime(stats.First, profile.Firefox);
        var last = ConvertTime(stats.Last, profile.Firefox);
        return Item("browser-status-" + StableId(profile.Browser + profile.Name), "browser_history_status", profile, last,
            "WD-BROWSER-HISTORY-STATUS", "none", "unknown",
            stats.Count == 0 ? "Історія браузера порожня. Це не підтверджує очищення: можливі новий профіль, приватний режим або автоматична політика видалення." : "Історію зіставлено локально. Передаються лише URL збігів і час відвідувань; стороння історія не передається.",
            new() { ["visits"] = stats.Count, ["first_visit"] = first, ["last_visit"] = last, ["database_created"] = Unix(info.CreationTimeUtc), ["database_modified"] = Unix(info.LastWriteTimeUtc), ["clear_time"] = "not_available" });
    }

    private static Evidence MatchEvidence(Profile profile, Rule rule, Visit visit)
    {
        var first = ConvertTime(visit.First, profile.Firefox);
        var last = ConvertTime(visit.Last, profile.Firefox);
        return Item("browser-match-" + StableId(profile.Browser + profile.Name + rule.Id + visit.Url + visit.Last), "browser_site_match", profile, last,
            rule.Id, "medium", "confirmed",
            $"У локальній історії {profile.Browser} є збіг із каталогом ресурсів ({rule.Label}). Сам факт відвідування не доводить придбання чи використання чита.",
            new() { ["catalog_version"] = BrowserIndicators.CatalogVersion, ["cheating_proof"] = false, ["matched_url"] = BrowserIndicators.ReportUrl(visit.Url), ["domain"] = rule.Host, ["visits"] = visit.Count, ["first_visit"] = first, ["last_visit"] = last });
    }

    private static IEnumerable<Evidence> FindReplacementArtifacts(Profile profile)
    {
        var folder = Path.GetDirectoryName(profile.Database)!;
        var names = profile.Firefox ? new[] { "places.sqlite.corrupt", "places.sqlite.bak" } : new[] { "History.old", "History.bak", "History.corrupt" };
        foreach (var name in names)
        {
            var path = Path.Combine(folder, name);
            if (!File.Exists(path)) continue;
            var info = new FileInfo(path);
            yield return Item("browser-change-" + StableId(profile.Browser + profile.Name + name), "browser_history_changed", profile, Unix(info.LastWriteTimeUtc),
                "WD-BROWSER-HISTORY-REPLACED", "low", "medium",
                "Поруч з активною history-базою знайдено резервний або corrupt-файл. Це свідчить про заміну/відновлення бази, але не доводить навмисне очищення.",
                new() { ["artifact"] = name, ["modified"] = Unix(info.LastWriteTimeUtc), ["size"] = info.Length });
        }
    }

    public static string? MatchRuleId(string url) => MatchRule(url)?.Id;

    private static Rule? MatchRule(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed) || parsed.Scheme is not ("http" or "https")) return null;
        var host = parsed.Host.TrimEnd('.');
        return Rules.FirstOrDefault(rule => (host.Equals(rule.Host, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + rule.Host, StringComparison.OrdinalIgnoreCase))
            && (rule.Id=="WD-WEB-VIDEO" ? (parsed.AbsolutePath=="/watch" && parsed.Query.TrimStart('?').Split('&').Contains("v=peXKyGX5n3s"))
                : rule.Id=="WD-WEB-VIDEO-SHORT" ? parsed.AbsolutePath.TrimEnd('/')=="/peXKyGX5n3s"
                : rule.Id is "WD-WEB-DIVINE-INVITE" or "WD-WEB-DIVINE-SHORT" ? parsed.AbsolutePath.TrimEnd('/').Equals(rule.PathNeedle,StringComparison.OrdinalIgnoreCase)
                : string.IsNullOrEmpty(rule.PathNeedle) || parsed.AbsolutePath.Contains(rule.PathNeedle, StringComparison.OrdinalIgnoreCase)
                    || (rule.PathNeedle.StartsWith("id=") && parsed.Query.TrimStart('?').Split('&').Contains(rule.PathNeedle))));
    }

    private static Evidence Item(string id, string type, Profile profile, double? timestamp, string rule, string severity, string confidence, string explanation, Dictionary<string, object?> details) =>
        new(id[..Math.Min(id.Length,60)] + "-" + StableId(profile.Database)[..12], type, "browser_history", timestamp, "UTC", "historical", "", "", "", "local_artifact", rule, severity, confidence, explanation,
            new(details) { ["browser"] = profile.Browser, ["profile"] = profile.Name });

    private static double? ConvertTime(long? value, bool firefox)
    {
        if (value is null or <= 0) return null;
        try { return firefox ? value.Value / 1_000_000d : DateTimeOffset.FromFileTime(value.Value * 10).ToUnixTimeMilliseconds() / 1000d; }
        catch { return null; }
    }

    private static string SafeFirefoxProfile(string name)
    {
        var separator = name.IndexOf('.');
        return separator >= 0 && separator < name.Length - 1 ? name[(separator + 1)..] : "Profile";
    }
    private static double Unix(DateTime value) => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)).ToUnixTimeMilliseconds() / 1000d;
    private static string StableId(string value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant()[..20];
    private static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000d;

    private sealed class DatabaseSnapshot : IDisposable
    {
        private readonly string _folder;
        public string Database { get; }
        private DatabaseSnapshot(string folder, string database) { _folder = folder; Database = database; }
        public static DatabaseSnapshot Create(string source)
        {
            var root = Path.Combine(Path.GetTempPath(), "WardogsScannerHistory");
            Directory.CreateDirectory(root);
            var folder = Path.Combine(root, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            var target = Path.Combine(folder, Path.GetFileName(source));
            try
            {
            CopyShared(source, target);
            foreach (var suffix in new[] { "-wal", "-shm" }) if (File.Exists(source + suffix)) CopyShared(source + suffix, target + suffix);
            return new(folder, target);
            }
            catch { new DatabaseSnapshot(folder,target).Dispose(); throw; }
        }
        private static void CopyShared(string source, string target)
        {
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
        }
        public void Dispose()
        {
            try
            {
                var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "WardogsScannerHistory"));
                var target = Path.GetFullPath(_folder);
                if (target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) Directory.Delete(target, true);
            }
            catch { }
        }
    }
}
