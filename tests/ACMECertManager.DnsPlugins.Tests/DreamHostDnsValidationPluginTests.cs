using System.Net;
using System.Net.Http;
using DreamHostDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class DreamHostDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "key"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_Succeeds()
    {
        using var http = HttpStub.Client(request =>
        {
            var url = HttpStub.Url(request);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Contains("https://api.dreamhost.com/", url, StringComparison.Ordinal);
            Assert.Contains("key=key", url, StringComparison.Ordinal);
            Assert.Contains("record=_acme-challenge.www.example.com", url, StringComparison.Ordinal);
            Assert.Contains("type=TXT", url, StringComparison.Ordinal);
            Assert.Contains("value=challenge-value", url, StringComparison.Ordinal);

            if (url.Contains("cmd=dns-add_record", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"result":"success"}""");
            }

            if (url.Contains("cmd=dns-remove_record", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"result":"success"}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {url}");
        });

        var plugin = new DreamHostDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }
}
