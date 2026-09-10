using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using TransIpDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class TransIpDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> TokenCredentials =
        new Dictionary<string, string>
        {
            ["accessToken"] = "jwt-token"
        };

    private static readonly string PrivateKeyPem = CreateTestPem();

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutBodySubstring()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);
            Assert.Equal("Bearer jwt-token", request.Headers.Authorization?.ToString());

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                return present
                    ? HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"dnsEntries":[{"name":"_acme-challenge.www","expire":60,"type":"TXT","content":"challenge-value"}]}""")
                    : HttpStub.Json(HttpStatusCode.OK, """{"dnsEntries":[]}""");
            }

            if (request.Method == HttpMethod.Get && path.StartsWith("/v6/domains/", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"Domain with name 'missing' not found"}""");
            }

            if (request.Method == HttpMethod.Post &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                Assert.Contains("\"type\":\"TXT\"", HttpStub.Body(request), StringComparison.Ordinal);
                Assert.Contains("challenge-value", HttpStub.Body(request), StringComparison.Ordinal);
                present = true;
                return new HttpResponseMessage(HttpStatusCode.Created);
            }

            if (request.Method == HttpMethod.Delete &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                present = false;
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new TransIpDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, TokenCredentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, TokenCredentials, CancellationToken.None);
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

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"dnsEntries":[]}""");
            }

            if (request.Method == HttpMethod.Get && path.StartsWith("/v6/domains/", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"not found"}""");
            }

            if (request.Method == HttpMethod.Post &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(status);
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new TransIpDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), TokenCredentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"error":"invalid token"}"""));
        var plugin = new TransIpDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), TokenCredentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_MissingZone_IsNotAuthFailure()
    {
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"Domain with name 'example.com' not found"}""");
        });
        var plugin = new TransIpDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), TokenCredentials, CancellationToken.None));

        Assert.Contains("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("authentication/authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PresentChallengeAsync_LoginAndPrivateKey_MintsTokenThenAddsTxt()
    {
        var minted = false;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Post && path.Equals("/v6/auth", StringComparison.Ordinal))
            {
                Assert.True(request.Headers.Contains("Signature"));
                Assert.Contains("\"login\":\"acct\"", HttpStub.Body(request), StringComparison.Ordinal);
                minted = true;
                return HttpStub.Json(HttpStatusCode.OK, """{"token":"minted-jwt"}""");
            }

            Assert.True(minted);
            Assert.Equal("Bearer minted-jwt", request.Headers.Authorization?.ToString());

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"dnsEntries":[]}""");
            }

            if (request.Method == HttpMethod.Get && path.StartsWith("/v6/domains/", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"not found"}""");
            }

            if (request.Method == HttpMethod.Post &&
                path.Equals("/v6/domains/example.com/dns", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.Created);
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new TransIpDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(
            HttpStub.Challenge(),
            new Dictionary<string, string>
            {
                ["login"] = "acct",
                ["privateKey"] = PrivateKeyPem
            },
            CancellationToken.None);
    }

    [Fact]
    public async Task PresentChallengeAsync_AuthMintFailure_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal("/v6/auth", HttpStub.Path(request));
            return HttpStub.Json(HttpStatusCode.Unauthorized, """{"error":"signature invalid"}""");
        });
        var plugin = new TransIpDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(
                HttpStub.Challenge(),
                new Dictionary<string, string>
                {
                    ["login"] = "acct",
                    ["privateKey"] = PrivateKeyPem
                },
                CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("signature invalid", ex.Message, StringComparison.Ordinal);
    }

    private static string CreateTestPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }
}
