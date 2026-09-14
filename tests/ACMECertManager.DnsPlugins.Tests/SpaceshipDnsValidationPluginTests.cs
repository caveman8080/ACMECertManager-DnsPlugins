using System.Net;
using System.Net.Http;
using SpaceshipDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class SpaceshipDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "key",
            ["apiSecret"] = "secret"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath()
    {
        var added = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal("key", request.Headers.GetValues("X-API-Key").Single());
            Assert.Equal("secret", request.Headers.GetValues("X-API-Secret").Single());
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get && path.Contains("/dns/records/", StringComparison.Ordinal))
            {
                var zone = path.Split('/').Last();
                return zone == "example.com"
                    ? HttpStub.Json(HttpStatusCode.OK, """{"items":[],"total":0}""")
                    : HttpStub.Json(HttpStatusCode.NotFound, """{"detail":"not found"}""");
            }

            if (request.Method == HttpMethod.Put)
            {
                var body = HttpStub.Body(request);
                Assert.Contains("\"force\":true", body, StringComparison.Ordinal);
                Assert.Contains("\"type\":\"TXT\"", body, StringComparison.Ordinal);
                Assert.Contains("_acme-challenge.www", body, StringComparison.Ordinal);
                Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                added = true;
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            if (request.Method == HttpMethod.Delete)
            {
                var body = HttpStub.Body(request);
                Assert.Contains("_acme-challenge.www", body, StringComparison.Ordinal);
                Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                added = false;
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new SpaceshipDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();
        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(added);
    }

    [Fact]
    public async Task Present_AuthFailure_IsNotMissingZone()
    {
        using var http = HttpStub.Client(_ => HttpStub.Json(HttpStatusCode.Unauthorized, """{"detail":"bad key"}"""));
        var plugin = new SpaceshipDnsValidationPlugin(http);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));
        HttpStub.AssertAuthFailure(ex);
    }
}
