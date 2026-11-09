using Wardogs.Scanner;
using Microsoft.Data.Sqlite;
using System.Text;
using System.Text.Json;

internal static class FixtureChecks
{
    public static void Run()
    {
        int checks=0;
        void Check(bool condition,string label) { if(!condition) throw new Exception(label);checks++; }
        Check(GameProcessGuard.IsGameProcess("Wardogs"), "game launcher blocked");
        Check(GameProcessGuard.IsGameProcess("Wardogs-Win64-Shipping"), "shipping game blocked");
        Check(GameProcessGuard.IsGameProcess("WARDOGS_Win64_Shipping"), "game case variant blocked");
        Check(!GameProcessGuard.IsGameProcess("WardogsScanner"), "scanner does not block itself");
        Check(!GameProcessGuard.IsGameProcess("notepad"), "unrelated process allowed");
        Check(BrowserHistoryCollector.MatchRuleId("https://buywardogscheat.org/store")!=null,"catalog match");
        Check(BrowserHistoryCollector.MatchRuleId("https://buywardogscheat.org.example.org/store")==null,"host suffix confusion");
        Check(BrowserHistoryCollector.MatchRuleId("https://example.org/?url=buywardogscheat.org")==null,"query host confusion");
        Check(BrowserHistoryCollector.MatchRuleId("file:///buywardogscheat.org")==null,"non web scheme");
        Check(BrowserIndicators.MatchKeywords("https://www.google.com/search?q=wardogs+aimbot").Contains("aimbot"),"keyword positive");
        Check(BrowserIndicators.MatchKeywords("https://example.org/wardogs-%D1%87%D1%96%D1%82%D0%B8").Contains("чіти"),"unicode keyword");
        Check(BrowserIndicators.MatchKeywords("https://example.org/wardogs-chitchat").Length==0,"word boundary");
        Check(BrowserIndicators.MatchKeywords("https://example.org/wardogs-anti-cheat").Length==0,"anti cheat negative");
        Check(BrowserIndicators.MatchKeywords("https://wardogs.com.ua/wardogs-cheats").Length==0,"own support negative");
        Check(BrowserIndicators.MatchKeywords("https://example.org/another-game-aimbot").Length==0,"game context required");
        foreach(var url in new[]{"https://divinedigital.cc/products/wardogs-software", "https://discord.com/invite/divineud", "https://www.privatecheatz.com/wardogs-hacks/", "https://ducks-services.com/store/category/186-wardogs/", "https://www.youtube.com/watch?v=peXKyGX5n3s", "https://cheatstore.net/", "https://burgercheats.com/", "https://shxdowcheats.net/", "https://ghost.one/", "https://hack-store.ru/", "https://cheatsforwardogs.net/", "https://syntheticskill.com/", "https://surchcheats.com/", "https://zsoft.store/", "https://badboycheats.com/"})
            Check(BrowserHistoryCollector.MatchRuleId(url)!=null,"supplied resource "+url);
        Check(BrowserIndicators.MatchKeywords("https://google.com/search?q="+Uri.EscapeDataString("чити для вардогс")).Length>0,"Cyrillic search");
        Check(BrowserIndicators.MatchKeywords("https://google.com/search?q=external+hack+war+dogs").Length>0,"reversed external search");
        Check(!BrowserIndicators.ReportUrl("https://user:password@example.org/wardogs-cheats?q=wardogs+aimbot&token=PRIVATE_SECRET#secret").Contains("PRIVATE_SECRET"),"URL token removed");
        Check(!BrowserIndicators.ReportUrl("https://user:password@example.org/wardogs-cheats").Contains("password"),"URL credentials removed");
        Check(MacroCollector.AnalyzeScript("-- no recoil\nMoveMouseRelative(0, 5)").Length==0,"movement alone is not macro");
        Check(MacroCollector.AnalyzeScript("-- MoveMouseRelative Loop IsMouseButtonPressed recoil").Length==0,"comment alone is not macro");
        Check(MacroCollector.AnalyzeScript("while IsMouseButtonPressed(1) do MoveMouseRelative(0, recoil) end").Length==3,"recoil macro features");
        Check(MacroCollector.AnalyzeScript("while GetKeyState(\"LButton\") { MouseMove 0, 4 }").Length==2,"AHK repeated input");
        Check(ExternalAccessCollector.IsMemoryAccess(0x10) && ExternalAccessCollector.IsMemoryAccess(0x20),"memory access masks");
        Check(!ExternalAccessCollector.IsMemoryAccess(0x1000),"query-only not memory access");
        Check(ModuleCollector.PrivateExecutable(0x1000,0x20000,0x40),"private executable metadata");
        Check(!ModuleCollector.PrivateExecutable(0x1000,0x1000000,0x20),"normal image mapping excluded");
        Check(!ModuleCollector.PrivateExecutable(0x1000,0x20000,0x4),"private data excluded");
        Check(BrowserHistoryCollector.MatchRuleId("https://youtube.com/watch?v=peXKyGX5n3sOTHER")==null,"different video not matched");
        Check(BrowserHistoryCollector.MatchRuleId("https://discord.com/invite/divineud-other")==null,"different invite not matched");
        Check(BrowserIndicators.ChromiumTimestamp("9223372036854775807")==null,"overflow");
        Check(BrowserIndicators.ChromiumTimestamp("1")==null,"ancient timestamp");
        var timestamp=DateTimeOffset.UtcNow.AddDays(-1);
        var prefs=JsonSerializer.Serialize(new {browser=new {last_clear_browsing_data_time=(timestamp.ToFileTime()/10).ToString()}});
        var markers=BrowserIndicators.AnalyzePreferences(prefs,false);
        Check(markers.Count==1 && Math.Abs(markers[0].Time!.Value-timestamp.ToUnixTimeSeconds())<2,"timestamp conversion");
        Check((string)markers[0].Details["history_cleared"]! == "not_determined","clear scope uncertain");
        Check(BrowserIndicators.AnalyzePreferences("user_pref(\"privacy.sanitize.sanitizeOnShutdown\", true); user_pref(\"privacy.clearOnShutdown.history\", true);",true).Count==1,"firefox clear policy");
        Check(BrowserIndicators.AnalyzePreferences("user_pref(\"privacy.sanitize.sanitizeOnShutdown\", false); user_pref(\"privacy.clearOnShutdown.history\", true);",true).Count==0,"firefox policy disabled");
        byte[] Record(string name,uint reason) {
            var bytes=Encoding.Unicode.GetBytes(name);var record=new byte[60+bytes.Length];
            BitConverter.GetBytes(record.Length).CopyTo(record,0);BitConverter.GetBytes((ushort)2).CopyTo(record,4);
            BitConverter.GetBytes((ulong)123).CopyTo(record,16);BitConverter.GetBytes((long)456).CopyTo(record,24);
            BitConverter.GetBytes(timestamp.ToFileTime()).CopyTo(record,32);BitConverter.GetBytes(reason).CopyTo(record,40);
            BitConverter.GetBytes((ushort)bytes.Length).CopyTo(record,56);BitConverter.GetBytes((ushort)60).CopyTo(record,58);bytes.CopyTo(record,60);return record;
        }
        var trace=BrowserJournalCollector.Parse(Record("History",0x200)).Single();
        Check(trace.Parent==123 && trace.Usn==456 && trace.Reason==0x200,"USN identity and reason");
        Check(BrowserJournalCollector.Parse(Record("History-wal",0x4)).Count==0,"normal WAL truncation excluded");
        Check(BrowserJournalCollector.Parse(Record("History",0x100)).Count==0,"create not delete");
        Check(BrowserJournalCollector.Parse(new byte[60]).Count==0,"corrupt USN bounded");
        var guard="\"guard\":{\"vbs\":2,\"running\":[2],\"configured\":[2],\"available\":[3]}";
        using(var doc=JsonDocument.Parse("{"+guard+",\"devices\":[{\"PNPDeviceID\":\"PCI\\\\VEN_10EE&DEV_0666\",\"Name\":\"FPGA\"}]}")) {
            var result=HardwareCollector.Analyze(doc.RootElement);
            Check(result.Count(x=>x.Type=="dma_device_candidate")==1,"DMA candidate");
            Check(result.All(x=>x.Severity is not ("critical" or "high")),"hardware not cheating proof");
        }
        using(var doc=JsonDocument.Parse("{"+guard+",\"devices\":[{\"PNPDeviceID\":\"PCI\\\\VEN_10EE&DEV_1234\",\"Name\":\"Legitimate FPGA\"}]}"))
            Check(HardwareCollector.Analyze(doc.RootElement).All(x=>x.Type!="dma_device_candidate"),"vendor alone insufficient");
        var root=Path.Combine(Path.GetTempPath(),"WardogsFixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try {
            var opera=Path.Combine(root,"Opera GX Stable");
            Directory.CreateDirectory(Path.Combine(opera,"Default"));
            Directory.CreateDirectory(Path.Combine(opera,"_side_profiles","profile1"));
            File.WriteAllText(Path.Combine(opera,"Default","History"),"");
            File.WriteAllText(Path.Combine(opera,"_side_profiles","profile1","History"),"");
            Check(BrowserHistoryCollector.OperaHistoryPaths(opera).Count()==2,"Opera GX nested profiles");
            foreach(var firefox in new[]{false,true}) {
                var folder=Path.Combine(root,firefox?"firefox":"chrome");Directory.CreateDirectory(folder);
                var database=Path.Combine(folder,firefox?"places.sqlite":"History");
                using(var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=database,Pooling=false}.ToString())) {
                    db.Open();using var cmd=db.CreateCommand();
                    cmd.CommandText=firefox?"CREATE TABLE moz_places(id INTEGER,url TEXT,visit_count INTEGER); CREATE TABLE moz_historyvisits(place_id INTEGER,visit_date INTEGER);":"CREATE TABLE urls(id INTEGER,url TEXT,visit_count INTEGER); CREATE TABLE visits(url INTEGER,visit_time INTEGER);";cmd.ExecuteNonQuery();
                    var empty=BrowserHistoryCollector.AnalyzeProfile(database,firefox);Check(empty.All(x=>x.Severity=="none"),"empty history not cleanup proof");
                    cmd.CommandText=firefox?"INSERT INTO moz_places VALUES(1,@url,1); INSERT INTO moz_historyvisits VALUES(1,@time);":"INSERT INTO urls VALUES(1,@url,1); INSERT INTO visits VALUES(1,@time);";
                    cmd.Parameters.AddWithValue("@url","https://google.com/search?q=wardogs+aimbot+PRIVATE_SENTINEL");cmd.Parameters.AddWithValue("@time",firefox?timestamp.ToUnixTimeSeconds()*1000000:timestamp.ToFileTime()/10);cmd.ExecuteNonQuery();
                }
                using(var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=database,Pooling=false}.ToString())) {
                    db.Open(); using var cmd=db.CreateCommand();
                    var table=firefox?"moz_places":"urls";
                    cmd.CommandText=$"WITH RECURSIVE n(x) AS (SELECT 2 UNION ALL SELECT x+1 FROM n WHERE x<50003) INSERT INTO {table} SELECT x, 'https://youtube.com/watch?v=ordinary-' || x, 1 FROM n";
                    cmd.ExecuteNonQuery();
                }
                var found=BrowserHistoryCollector.AnalyzeProfile(database,firefox);
                Check(found.Count(x=>x.Type=="browser_keyword_match")==1,"SQLite keyword evidence");
                Check(JsonSerializer.Serialize(found).Contains("PRIVATE_SENTINEL"),"matched search URL retained with consent");
                Check(found.Single(x=>x.Type=="browser_keyword_match").Details.ContainsKey("last_visit"),"matched visit date retained");
                Check(found.Select(x=>x.EvidenceId).Distinct().Count()==found.Count,"unique evidence ids");
                Check(!found.Any(x=>x.RuleId=="WD-BROWSER-HISTORY-LIMIT"),"ordinary 50000+ video URLs do not consume match budget");
                using(var db=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=database,Pooling=false}.ToString())) {
                    db.Open(); using var cmd=db.CreateCommand();
                    cmd.CommandText=$"UPDATE {(firefox?"moz_places":"urls")} SET url='https://buywardogscheat.org/item/' || id WHERE id>1";
                    cmd.ExecuteNonQuery();
                }
                var capped=BrowserHistoryCollector.AnalyzeProfile(database,firefox);
                Check(capped.Any(x=>x.RuleId=="WD-BROWSER-HISTORY-LIMIT"),"real match overflow reports partial coverage without throwing");
                Check(capped.Count(x=>x.Type is "browser_site_match" or "browser_keyword_match")==50000,"match budget bounded");

            }
            var missing=BrowserHistoryCollector.AnalyzeProfile(Path.Combine(root,"absent"),false);
            Check(missing.All(x=>x.Severity=="none"),"missing history not guilty");
        } finally { Directory.Delete(root,true); }
        var smbios=new byte[34];BitConverter.GetBytes((uint)26).CopyTo(smbios,4);smbios[8]=1;smbios[9]=24;
        for(int i=0;i<16;i++) smbios[16+i]=(byte)(i+1);
        var identity=DeviceIdentityCollector.FromSmbios(smbios);
        Check(identity is {Kind:"smbios_uuid_v1"} && identity.Digest.Length==64,"hashed hardware identity");
        Check(identity==DeviceIdentityCollector.FromSmbios(smbios),"stable identity");
        smbios[16]=99;Check(identity!=DeviceIdentityCollector.FromSmbios(smbios),"different hardware identity");
        Array.Fill<byte>(smbios,0,16,16);Check(DeviceIdentityCollector.FromSmbios(smbios)==null,"empty UUID rejected");
        Array.Fill<byte>(smbios,255,16,16);Check(DeviceIdentityCollector.FromSmbios(smbios)==null,"OEM placeholder rejected");
        Check(DeviceIdentityCollector.FromSmbios(smbios.AsSpan(0,20))==null,"truncated SMBIOS rejected");
        Check(BrowserIndicators.AnalyzePreferences("user_pref(\"privacy.sanitize.sanitizeOnShutdown\", true); user_pref(\"privacy.clearOnShutdown_v2.browsingHistoryAndDownloads\", true);",true).Count==1,"current Firefox policy");
        Console.WriteLine($"PASS {checks} offline fixture checks; no user history scanned");
    }
}
