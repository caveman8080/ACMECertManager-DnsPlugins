using System.Net;
using System.Net.Http;
using NjallaDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class NjallaDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiToken"] = "token"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutTxtSubstring()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/api/1/", HttpStub.Path(request));
            Assert.Equal("Njalla token", request.Headers.GetValues("Authorization").Single());

            var body = HttpStub.Body(request);
            var domain = ReadParam(body, "domain");

            if (body.Contains("\"get-domain\"", StringComparison.Ordinal))
            {
                if (string.Equals(domain, "example.com", StringComparison.Ordinal))
                {
                    return HttpStub.Json(HttpStatusCode.OK, """{"jsonrpc":"2.0","result":{"name":"example.com"}}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"jsonrpc":"2.0","error":{"code":403,"message":"permission denied"}}""");
            }

            if (body.Contains("\"list-records\"", StringComparison.Ordinal))
            {
                Assert.Equal("example.com", domain);
                return present
                    ? HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"jsonrpc":"2.0","result":{"records":[{"id":99,"type":"TXT","name":"_acme-challenge.www","content":"challenge-value"}]}}""")
                    : HttpStub.Json(HttpStatusCode.OK, """{"jsonrpc":"2.0","result":{"records":[]}}""");
            }

            if (body.Contains("\"add-record\"", StringComparison.Ordinal))
            {
                Assert.Contains("\"type\":\"TXT\"", body, StringComparison.Ordinal);
                Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                present = true;
                return HttpStub.Json(HttpStatusCode.OK, """{"jsonrpc":"2.0","result":{"id":99}}""");
            }

            if (body.Contains("\"remove-record\"", StringComparison.Ordinal))
            {
                Assert.Contains("\"id\":99", body, StringComparison.Ordinal);
                present = false;
                return HttpStub.Json(HttpStatusCode.OK, """{"jsonrpc":"2.0","result":{}}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new NjallaDnsValidationPlugin(http);
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
            var body = HttpStub.Body(request);
            var domain = ReadParam(body, "domain");

            if (body.Contains("\"get-domain\"", StringComparison.Ordinal))
            {
                if (string.Equals(domain, "example.com", StringComparison.Ordinal))
                {
                    return HttpStub.Json(HttpStatusCode.OK, """{"result":{"name":"example.com"}}""");
                }

                return HttpStub.Json(HttpStatusCode.OK, """{"error":{"code":403,"message":"permission denied"}}""");
            }

            if (body.Contains("\"list-records\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"result":{"records":[]}}""");
            }

            if (body.Contains("\"add-record\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(status, """{"result":{}}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new NjallaDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"error":"invalid token"}"""));
        var plugin = new NjallaDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_JsonRpcInvalidToken_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(
                HttpStatusCode.OK,
                """{"jsonrpc":"2.0","error":{"code":403,"message":"Invalid token"}}"""));
        var plugin = new NjallaDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("Invalid token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_MissingZone_IsNotAuthFailure()
    {
        using var http = HttpStub.Client(request =>
        {
            Assert.Contains("\"get-domain\"", HttpStub.Body(request), StringComparison.Ordinal);
            return HttpStub.Json(
                HttpStatusCode.OK,
                """{"jsonrpc":"2.0","error":{"code":403,"message":"permission denied"}}""");
        });
        var plugin = new NjallaDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        Assert.Contains("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("authentication/authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string? ReadParam(string body, string name)
    {
        var needle = $"\"{name}\":\"";
        var start = body.IndexOf(needle, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += needle.Length;
        var end = body.IndexOf('"', start);
        return end < 0 ? null : body[start..end];
    }
}
