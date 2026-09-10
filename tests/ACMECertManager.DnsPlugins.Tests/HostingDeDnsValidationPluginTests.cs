using System.Net;
using System.Net.Http;
using HostingDeDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class HostingDeDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["authToken"] = "token"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutTxtSubstring()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            var path = HttpStub.Path(request);
            var body = HttpStub.Body(request);
            Assert.Contains("\"authToken\":\"token\"", body, StringComparison.Ordinal);

            if (path.Equals("/api/dns/v1/json/zoneConfigsFind", StringComparison.Ordinal))
            {
                var zone = ReadFilterValue(body);
                if (string.Equals(zone, "example.com", StringComparison.Ordinal))
                {
                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"success","response":{"data":[{"id":"zone-1","name":"example.com","type":"NATIVE"}],"totalEntries":1}}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"status":"success","response":{"data":[],"totalEntries":0}}""");
            }

            if (path.Equals("/api/dns/v1/json/recordsFind", StringComparison.Ordinal))
            {
                Assert.Contains("zone-1", body, StringComparison.Ordinal);
                return present
                    ? HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"success","response":{"data":[{"id":"rec-1","name":"_acme-challenge.www.example.com","type":"TXT","content":"\"challenge-value\""}]}}""")
                    : HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"success","response":{"data":[],"totalEntries":0}}""");
            }

            if (path.Equals("/api/dns/v1/json/zoneUpdate", StringComparison.Ordinal))
            {
                Assert.Contains("\"id\":\"zone-1\"", body, StringComparison.Ordinal);
                if (body.Contains("\"recordsToDelete\"", StringComparison.Ordinal))
                {
                    Assert.Contains("\"id\":\"rec-1\"", body, StringComparison.Ordinal);
                    present = false;
                    return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","response":{}}""");
                }

                Assert.Contains("\"recordsToAdd\"", body, StringComparison.Ordinal);
                Assert.Contains("\"type\":\"TXT\"", body, StringComparison.Ordinal);
                Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                present = true;
                return HttpStub.Json(HttpStatusCode.OK, """{"status":"pending","response":{}}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new HostingDeDnsValidationPlugin(http);
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
            var path = HttpStub.Path(request);
            var body = HttpStub.Body(request);

            if (path.Equals("/api/dns/v1/json/zoneConfigsFind", StringComparison.Ordinal))
            {
                if (string.Equals(ReadFilterValue(body), "example.com", StringComparison.Ordinal))
                {
                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"success","response":{"data":[{"id":"zone-1","name":"example.com"}]}}""");
                }

                return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","response":{"data":[]}}""");
            }

            if (path.Equals("/api/dns/v1/json/recordsFind", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","response":{"data":[]}}""");
            }

            if (path.Equals("/api/dns/v1/json/zoneUpdate", StringComparison.Ordinal))
            {
                return HttpStub.Json(status, """{"status":"pending"}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new HostingDeDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"status":"error","errors":[{"text":"invalid token"}]}"""));
        var plugin = new HostingDeDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_ApiKeyError10109_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(
                HttpStatusCode.OK,
                """{"status":"error","errors":[{"code":10109,"context":"authToken","text":"The API-Key is invalid or could not be found"}]}"""));
        var plugin = new HostingDeDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("10109", ex.Message, StringComparison.Ordinal);
        Assert.Contains("API-Key is invalid", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PresentChallengeAsync_MissingZone_IsNotAuthFailure()
    {
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal("/api/dns/v1/json/zoneConfigsFind", HttpStub.Path(request));
            return HttpStub.Json(
                HttpStatusCode.OK,
                """{"status":"success","response":{"data":[],"totalEntries":0}}""");
        });
        var plugin = new HostingDeDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        Assert.Contains("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("authentication/authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string? ReadFilterValue(string body)
    {
        const string needle = "\"value\":\"";
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
