using System.Net;
using System.Net.Http;
using System.Text.Json;
using Wardogs.Scanner;

static class OfflineFixtures
{
    static void Check(bool value, string name) { if (!value) throw new Exception(name); }
    sealed class ResponseHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
    }
    public static async Task Run()
    {
        var folder = Path.Combine(Path.GetTempPath(), "wd-offline-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var broken = Path.Combine(folder, "BROKEN.EXE-1234.pf");
            File.WriteAllBytes(broken, [1, 2, 3, 4]);
            var item = AdvancedCollector.CollectPrefetchFile(broken, new Dictionary<string, string>());
            Check((string?)item.Details["parse_status"] == "error", "Corrupt file must be marked");
            Check(((string)item.Details["error"]!).Contains("Invalid Prefetch header"), "Exact parse reason");
            Check((string?)item.Details["prefetch_file"] == Path.GetFileName(broken), "File identity retained");
            var missing = AdvancedCollector.CollectPrefetchFile(Path.Combine(folder, "missing.pf"), new Dictionary<string, string>());
            Check(missing.Details.ContainsKey("error"), "Continue to next inaccessible file");
            var stages = new List<ModuleResult>(); var errors = new List<string>();
            CollectionSafety.Run("broken", () => throw new InvalidDataException("fixture failure"), stages, errors);
            CollectionSafety.Run("next", () => stages.Add(new("next", "success", 1, 1, 1, "")), stages, errors);
            Check(stages.Count == 2 && stages[0].Status == "error" && stages[1].Status == "success", "Stage isolation");
            var failed = await CollectionSafety.RunAsync<int>(() => throw new InvalidDataException("sync failure"), _ => 42);
            Check(failed == 42, "Synchronous collector failure isolated");
            failed = await CollectionSafety.RunAsync(() => Task.FromException<int>(new InvalidDataException()), _ => 43);
            Check(failed == 43, "Asynchronous collector failure isolated");
            try { await CollectionSafety.RunAsync<int>(() => throw new OperationCanceledException(), _ => 0); throw new Exception("Cancellation swallowed"); }
            catch (OperationCanceledException) { }
            foreach (var status in new[] { HttpStatusCode.ServiceUnavailable, HttpStatusCode.RequestTimeout, HttpStatusCode.TooManyRequests, HttpStatusCode.Forbidden })
            {
                var api = new ApiClient(new HttpClient(new ResponseHandler(status, "unavailable")));
                try { await api.StartAsync("https://fixture.invalid", "incident", "secret-code", new(1, "0.7.7", new string('a', 64)), CancellationToken.None); throw new Exception("Failure expected"); }
                catch (HttpRequestException ex) { Check(ApiClient.IsConnectionFailure(ex), "Network fallback classification"); }
            }
            var rejected = new ApiClient(new HttpClient(new ResponseHandler(HttpStatusCode.Unauthorized, "invalid code")));
            try { await rejected.StartAsync("https://fixture.invalid", "incident", "secret-code", new(1, "0.7.7", new string('a', 64)), CancellationToken.None); throw new Exception("Rejection expected"); }
            catch (InvalidOperationException ex) { Check(!ApiClient.IsConnectionFailure(ex), "Invalid code remains explicit"); }
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var report = new ScanReport(1, "", "0.7.7", new string('a', 64), now, now, true,
                new(true, ["processes", "transfer"]), stages, [item], errors);
            var envelope = OfflineReport.Create("", report);
            var path = await envelope.SaveAsync(folder);
            var json = File.ReadAllText(path);
            var restored = JsonSerializer.Deserialize<OfflineReport>(json)!;
            Check(restored.Report.Evidence.Count == 1 && restored.Report.SteamId == "" && restored.FormatVersion == 1, "Portable report roundtrip");
            Check(!json.Contains("secret-code") && !json.Contains("upload_token"), "No credentials exported");
            Check(!Directory.EnumerateFiles(folder, "*.tmp").Any(), "Atomic save finalized");
            try { await envelope.SaveAsync(broken); throw new Exception("Save failure expected"); }
            catch (IOException) { }
            var retried = await envelope.SaveAsync(folder);
            Check(File.Exists(retried) && retried != path, "Retry preserves report, no overwrite");
            Console.WriteLine("PASS: per-file errors, later stages, sync/async faults, cancellation, network fallback, rejected code, offline JSON, atomic save/retry");
        }
        finally { Directory.Delete(folder, true); }
    }
}
