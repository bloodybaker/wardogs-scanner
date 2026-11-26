using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Http;
namespace Wardogs.Scanner;

public sealed class ApiClient
{
    public static bool IsConnectionFailure(Exception ex) => ex is HttpRequestException or OperationCanceledException or System.Text.Json.JsonException;
    private readonly HttpClient _http;
    public ApiClient(HttpClient? http = null) => _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    public async Task<StartResponse> StartAsync(string apiBase, string incidentId, string challenge, StartRequest payload, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{apiBase.TrimEnd('/')}/api/v1/scans/{incidentId}/start") { Content = JsonContent.Create(payload) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", challenge);
        using var response = await _http.SendAsync(request, token);
        var body = await response.Content.ReadAsStringAsync(token);
        if ((int)response.StatusCode >= 500 || response.StatusCode is System.Net.HttpStatusCode.RequestTimeout or System.Net.HttpStatusCode.Forbidden || (int)response.StatusCode == 429)
            throw new HttpRequestException($"Сайт тимчасово недоступний ({(int)response.StatusCode}).");
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Сервер відхилив код ({(int)response.StatusCode}).");
        var session = System.Text.Json.JsonSerializer.Deserialize<StartResponse>(body);
        if (session == null || session.IncidentId != incidentId || session.SteamId?.Length != 17
            || !session.SteamId.All(char.IsAsciiDigit) || string.IsNullOrWhiteSpace(session.UploadToken))
            throw new HttpRequestException("Некоректна відповідь сервера. Звіт буде збережено офлайн.");
        return session;
    }
    public async Task<SubmitResponse> SubmitAsync(string apiBase, string incidentId, string uploadToken, ScanReport payload, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{apiBase.TrimEnd('/')}/api/v1/scans/{incidentId}/report") { Content = JsonContent.Create(payload) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", uploadToken);
        using var response = await _http.SendAsync(request, token);
        var body = await response.Content.ReadAsStringAsync(token);
        if ((int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.RequestTimeout || (int)response.StatusCode == 429)
            throw new HttpRequestException($"Сайт тимчасово недоступний ({(int)response.StatusCode}).");
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Сервер не прийняв звіт ({(int)response.StatusCode}).");
        return System.Text.Json.JsonSerializer.Deserialize<SubmitResponse>(body) ?? throw new InvalidOperationException("Некоректна відповідь сервера.");
    }
}
