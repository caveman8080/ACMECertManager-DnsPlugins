using System.Net;
using System.Net.Http;
using InfomaniakDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class InfomaniakDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiToken"] = "token"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutResultSuccessSubstring()
    {
        string? recordId = null;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get &&
                path.StartsWith("/2/domains/", StringComparison.Ordinal) &&
                path.EndsWith("/zones", StringComparison.Ordinal))
            {
                if (path.Contains("/domains/example.com/", StringComparison.Ordinal))
                {
                    return HttpStub.Json(HttpStatusCode.OK, """{"data":[{"fqdn":"example.com"}]}""");
                }

                return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"not_found"}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.StartsWith("/2/zones/", StringComparison.Ordinal) &&
                !path.Contains("/records", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"not_found"}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.Equals("/2/zones/example.com/records", StringComparison.Ordinal))
            {
                if (recordId is null)
                {
                    return HttpStub.Json(HttpStatusCode.OK, """{"data":[]}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"data":[{"id":"1","type":"TXT","source":"_acme-challenge.www","target":"challenge-value"}]}""");
            }

            if (request.Method == HttpMethod.Post &&
                path.Equals("/2/zones/example.com/records", StringComparison.Ordinal))
            {
                recordId = "1";
                return HttpStub.Json(HttpStatusCode.Created, """{"data":{"id":"1"}}""");
            }

            if (request.Method == HttpMethod.Delete &&
                path.StartsWith("/2/zones/example.com/records/", StringComparison.Ordinal))
            {
                recordId = null;
                return HttpStub.Json(HttpStatusCode.NoContent, "{}");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new InfomaniakDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"error":"invalid_token"}"""));
        var plugin = new InfomaniakDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid_token", ex.Message, StringComparison.Ordinal);
    }
}
