using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Http;
namespace Wardogs.Scanner;

public sealed class ApiClient
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromMinutes(2) };
    public async Task<StartResponse> StartAsync(string apiBase, string incidentId, string challenge, StartRequest payload, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{apiBase.TrimEnd('/')}/api/v1/scans/{incidentId}/start") { Content = JsonContent.Create(payload) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", challenge);
        using var response = await _http.SendAsync(request, token);
        var body = await response.Content.ReadAsStringAsync(token);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Сервер відхилив код ({(int)response.StatusCode}).");
        return System.Text.Json.JsonSerializer.Deserialize<StartResponse>(body) ?? throw new InvalidOperationException("Некоректна відповідь сервера.");
    }
    public async Task<SubmitResponse> SubmitAsync(string apiBase, string incidentId, string uploadToken, ScanReport payload, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{apiBase.TrimEnd('/')}/api/v1/scans/{incidentId}/report") { Content = JsonContent.Create(payload) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", uploadToken);
        using var response = await _http.SendAsync(request, token);
        var body = await response.Content.ReadAsStringAsync(token);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Сервер не прийняв звіт ({(int)response.StatusCode}).");
        return System.Text.Json.JsonSerializer.Deserialize<SubmitResponse>(body) ?? throw new InvalidOperationException("Некоректна відповідь сервера.");
    }
}
