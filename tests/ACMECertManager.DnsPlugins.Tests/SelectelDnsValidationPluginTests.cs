using System.Net;
using System.Net.Http;
using SelectelDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class SelectelDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> V2Credentials =
        new Dictionary<string, string>
        {
            ["loginId"] = "12345",
            ["projectName"] = "project",
            ["loginName"] = "svc",
            ["password"] = "pw"
        };

    [Fact]
    public async Task PresentAndCleanup_V2HappyPath_Succeeds()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Post &&
                path.Contains("/identity/v3/auth/tokens", StringComparison.Ordinal))
            {
                var response = HttpStub.Json(HttpStatusCode.Created, """{"token":{"expires_at":"2099-01-01T00:00:00Z"}}""");
                response.Headers.TryAddWithoutValidation("X-Subject-Token", "kstoken");
                return response;
            }

            if (request.Method == HttpMethod.Get &&
                path.Equals("/domains/v2/zones", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"count":1,"result":[{"id":"zone-1","name":"example.com."}]}""");
            }

            if (path.Equals("/domains/v2/zones/zone-1/rrset", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                {
                    if (!present)
                    {
                        return HttpStub.Json(HttpStatusCode.OK, """{"count":0,"result":[]}""");
                    }

                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"count":1,"result":[{"id":"rr-1","name":"_acme-challenge.www.example.com.","type":"TXT","records":[{"content":"\"challenge-value\""}]}]}""");
                }

                if (request.Method == HttpMethod.Post)
                {
                    present = true;
                    return HttpStub.Json(HttpStatusCode.Created, """{"id":"rr-1"}""");
                }
            }

            if (request.Method == HttpMethod.Delete &&
                path.Equals("/domains/v2/zones/zone-1/rrset/rr-1", StringComparison.Ordinal))
            {
                present = false;
                return HttpStub.Json(HttpStatusCode.NoContent, "");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new SelectelDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, V2Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, V2Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.Created)]
    [InlineData(HttpStatusCode.NoContent)]
    public async Task PresentChallengeAsync_Http2xxWithoutBodySubstring_Succeeds(HttpStatusCode status)
    {
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Post &&
                path.Contains("/identity/v3/auth/tokens", StringComparison.Ordinal))
            {
                var response = HttpStub.Json(HttpStatusCode.Created, "{}");
                response.Headers.TryAddWithoutValidation("X-Subject-Token", "kstoken");
                return response;
            }

            if (request.Method == HttpMethod.Get &&
                path.Equals("/domains/v2/zones", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"result":[{"id":"zone-1","name":"example.com."}]}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.Equals("/domains/v2/zones/zone-1/rrset", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"result":[]}""");
            }

            if (request.Method == HttpMethod.Post &&
                path.Equals("/domains/v2/zones/zone-1/rrset", StringComparison.Ordinal))
            {
                return HttpStub.Json(status, "{}");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new SelectelDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), V2Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"error":{"message":"invalid credentials"}}"""));
        var plugin = new SelectelDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), V2Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid credentials", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_V1ApiKey_UsesLegacyEndpoint()
    {
        var added = false;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);
            Assert.False(path.Contains("/identity/", StringComparison.Ordinal));

            if (request.Method == HttpMethod.Get && path.Equals("/domains/v1/", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """[{"id":11,"name":"example.com"}]""");
            }

            if (request.Method == HttpMethod.Get && path.Equals("/domains/v1/11/records/", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, added
                    ? """[{"id":99,"type":"TXT","name":"_acme-challenge.www.example.com","content":"challenge-value"}]"""
                    : "[]");
            }

            if (request.Method == HttpMethod.Post && path.Equals("/domains/v1/11/records/", StringComparison.Ordinal))
            {
                added = true;
                return HttpStub.Json(HttpStatusCode.Created, """{"id":99}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new SelectelDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(
            HttpStub.Challenge(),
            new Dictionary<string, string> { ["apiKey"] = "legacy-key" },
            CancellationToken.None);
    }
}
