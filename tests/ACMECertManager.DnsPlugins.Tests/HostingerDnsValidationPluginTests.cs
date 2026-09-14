using System.Net;
using System.Net.Http;
using HostingerDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class HostingerDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiToken"] = "hostinger-token"
        };

    private const string ZoneJson = """
        [
          {
            "name": "_acme-challenge.www",
            "records": [{ "content": "challenge-value", "is_disabled": false }],
            "ttl": 120,
            "type": "TXT"
          },
          {
            "name": "@",
            "records": [{ "content": "1.2.3.4", "is_disabled": false }],
            "ttl": 14400,
            "type": "A"
          }
        ]
        """;

    [Fact]
    public async Task PresentAndCleanup_DeletesWhenLastTxt()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("hostinger-token", request.Headers.Authorization?.Parameter);
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get)
            {
                if (path.EndsWith("/example.com", StringComparison.Ordinal))
                {
                    return HttpStub.Json(HttpStatusCode.OK, present ? ZoneJson : """[{"name":"@","records":[{"content":"1.2.3.4"}],"type":"A"}]""");
                }

                return HttpStub.Json(HttpStatusCode.NotFound, """{"message":"not found"}""");
            }

            if (request.Method == HttpMethod.Put)
            {
                var body = HttpStub.Body(request);
                Assert.Contains("\"overwrite\":false", body, StringComparison.Ordinal);
                Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                present = true;
                return HttpStub.Json(HttpStatusCode.OK, """{"message":"Request accepted"}""");
            }

            if (request.Method == HttpMethod.Delete)
            {
                var body = HttpStub.Body(request);
                Assert.Contains("\"name\":\"_acme-challenge.www\"", body, StringComparison.Ordinal);
                Assert.Contains("\"type\":\"TXT\"", body, StringComparison.Ordinal);
                present = false;
                return HttpStub.Json(HttpStatusCode.OK, """{"message":"Request accepted"}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new HostingerDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();
        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }
}
