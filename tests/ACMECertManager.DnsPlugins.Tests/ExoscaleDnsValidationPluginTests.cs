using System.Net;
using System.Net.Http;
using ExoscaleDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class ExoscaleDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "EXOKEY",
            ["apiSecret"] = "secret"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_Succeeds()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            AssertSigned(request);
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v2/dns-domain", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"dns-domains":[{"id":"zone-1","unicode-name":"example.com"}]}""");
            }

            if (path.Equals("/v2/dns-domain/zone-1/record", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                {
                    return present
                        ? HttpStub.Json(
                            HttpStatusCode.OK,
                            """{"dns-domain-records":[{"id":"rec-1","type":"TXT","name":"_acme-challenge.www","content":"\"challenge-value\""}]}""")
                        : HttpStub.Json(HttpStatusCode.OK, """{"dns-domain-records":[]}""");
                }

                if (request.Method == HttpMethod.Post)
                {
                    var body = HttpStub.Body(request);
                    Assert.Contains("\"type\":\"TXT\"", body, StringComparison.Ordinal);
                    Assert.Contains("\"name\":\"_acme-challenge.www\"", body, StringComparison.Ordinal);
                    Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                    present = true;
                    return HttpStub.Json(HttpStatusCode.OK, """{"id":"op-1","state":"success"}""");
                }
            }

            if (request.Method == HttpMethod.Delete &&
                path.Equals("/v2/dns-domain/zone-1/record/rec-1", StringComparison.Ordinal))
            {
                present = false;
                return HttpStub.Json(HttpStatusCode.OK, """{"id":"op-2","state":"success"}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new ExoscaleDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.Created)]
    [InlineData(HttpStatusCode.NoContent)]
    public async Task PresentChallengeAsync_Http2xxWithoutBodySubstring_Succeeds(HttpStatusCode status)
    {
        using var http = HttpStub.Client(request =>
        {
            AssertSigned(request);
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v2/dns-domain", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"dns-domains":[{"id":"zone-1","unicode-name":"example.com"}]}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v2/dns-domain/zone-1/record", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"dns-domain-records":[]}""");
            }

            if (request.Method == HttpMethod.Post &&
                path.Equals("/v2/dns-domain/zone-1/record", StringComparison.Ordinal))
            {
                return HttpStub.Json(status, "{}");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new ExoscaleDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"message":"invalid credentials"}"""));
        var plugin = new ExoscaleDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid credentials", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_MissingZone_IsNotAuthFailure()
    {
        using var http = HttpStub.Client(request =>
        {
            AssertSigned(request);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("/v2/dns-domain", HttpStub.Path(request));
            return HttpStub.Json(
                HttpStatusCode.OK,
                """{"dns-domains":[{"id":"other","unicode-name":"other.com"}]}""");
        });
        var plugin = new ExoscaleDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        Assert.Contains("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("authentication/authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static void AssertSigned(HttpRequestMessage request)
    {
        var authorization = request.Headers.GetValues("Authorization").Single();
        Assert.StartsWith("EXO2-HMAC-SHA256 credential=EXOKEY,", authorization, StringComparison.Ordinal);
        Assert.Contains("expires=", authorization, StringComparison.Ordinal);
        Assert.Contains("signature=", authorization, StringComparison.Ordinal);
    }
}
