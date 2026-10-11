using System.Net.Http.Headers;
using System.Text.Json;

var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");

string? token = Environment.GetEnvironmentVariable("LH_TOKEN");
var endpoints = args.Length > 0 ? args : new[] { "https://example.tld/api/me" };

var results = new List<object>();
using var sem = new SemaphoreSlim(8);

var tasks = endpoints.Select(async ep =>
{
    await sem.WaitAsync();
    try
    {
        var authed   = await Fetch(client, ep, token);
        var unauthed = await Fetch(client, ep, null);
        results.Add(new {
            endpoint = ep,
            authed   = new { authed.Status, authed.Len },
            unauthed = new { unauthed.Status, unauthed.Len },
            leak     = unauthed.Status == 200 && unauthed.Len > 0 && unauthed.Len == authed.Len
        });
    }
    finally { sem.Release(); }
});

await Task.WhenAll(tasks);
Console.WriteLine(JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));

static async Task<(int Status, long Len)> Fetch(HttpClient c, string url, string? token)
{
    using var req = new HttpRequestMessage(HttpMethod.Get, url);
    if (!string.IsNullOrEmpty(token))
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    try
    {
        using var resp = await c.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        return ((int)resp.StatusCode, body.LongLength);
    }
    catch { return (0, 0); }
}