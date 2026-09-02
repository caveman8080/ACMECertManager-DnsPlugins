using System.Net;
using System.Net.Http;
using System.Text;
using ACMECertManager;

namespace ACMECertManager.DnsPlugins.Tests;

internal sealed class ScriptedHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _send;

    public ScriptedHandler(Func<HttpRequestMessage, HttpResponseMessage> send)
    {
        _send = send;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken) =>
        Task.FromResult(_send(request));
}

internal static class HttpStub
{
    public static DnsChallengeRequest Challenge() =>
        new()
        {
            Domain = "www.example.com",
            RecordName = "_acme-challenge.www.example.com",
            Token = "token",
            KeyAuthorization = "token.thumbprint",
            TxtValue = "challenge-value"
        };

    public static HttpClient Client(Func<HttpRequestMessage, HttpResponseMessage> send) =>
        new(new ScriptedHandler(send), disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

    public static string Path(HttpRequestMessage request) =>
        request.RequestUri?.AbsolutePath ?? string.Empty;

    public static string Url(HttpRequestMessage request) =>
        request.RequestUri?.ToString() ?? string.Empty;

    public static void AssertAuthFailure(InvalidOperationException ex)
    {
        Assert.Contains("authentication/authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
