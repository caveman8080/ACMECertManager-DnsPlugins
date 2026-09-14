using System.Net;
using System.Net.Http;
using NoIpDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class NoIpDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "noip-key"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("noip-key", request.Headers.Authorization?.Parameter);
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get && path.StartsWith("/v1/dns/zones/", StringComparison.Ordinal))
            {
                return path.EndsWith("/example.com", StringComparison.Ordinal)
                    ? HttpStub.Json(HttpStatusCode.OK, """{"data":{"name":"example.com"}}""")
                    : HttpStub.Json(HttpStatusCode.NotFound, """{"errors":[{"id":"e","code":"2510","title":"zone not found"}]}""");
            }

            if (request.Method == HttpMethod.Post && path.EndsWith("/rrsets/TXT/rdata", StringComparison.Ordinal))
            {
                Assert.Contains("challenge-value", HttpStub.Body(request), StringComparison.Ordinal);
                present = true;
                return HttpStub.Json(HttpStatusCode.Created, "{}");
            }

            if (request.Method == HttpMethod.Post && path.EndsWith("/publish", StringComparison.Ordinal))
            {
                return HttpStub.Json((HttpStatusCode)202, "{}");
            }

            if (request.Method == HttpMethod.Get && path.EndsWith("/rrsets/TXT", StringComparison.Ordinal))
            {
                return present
                    ? HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"data":{"name":"_acme-challenge.www","dns_type":"TXT","rdata":[{"value":"challenge-value","label":"lbl1"}]}}""")
                    : HttpStub.Json(HttpStatusCode.NotFound, """{"errors":[{"id":"e","code":"2373","title":"RRset not found"}]}""");
            }

            if (request.Method == HttpMethod.Delete && path.Contains("/rdata/lbl1", StringComparison.Ordinal))
            {
                present = false;
                return HttpStub.Json(HttpStatusCode.OK, "{}");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new NoIpDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();
        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }
}
