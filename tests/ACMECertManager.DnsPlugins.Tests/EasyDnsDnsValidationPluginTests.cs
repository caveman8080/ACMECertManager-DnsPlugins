using System.Net;
using System.Net.Http;
using EasyDnsDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class EasyDnsDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiToken"] = "token",
            ["apiKey"] = "key"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_Succeeds()
    {
        string? recordId = null;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get &&
                path.Contains("/zones/records/all/example.com/search/", StringComparison.Ordinal))
            {
                if (recordId is null)
                {
                    return HttpStub.Json(HttpStatusCode.OK, """{"status":200,"data":[]}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"status":200,"data":[{"id":"99","type":"TXT","host":"_acme-challenge.www","rdata":"challenge-value"}]}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.EndsWith("/zones/records/all/example.com", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"status":200,"data":[]}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.Contains("/zones/records/all/", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.NotFound, """{"status":404}""");
            }

            if (request.Method == HttpMethod.Put &&
                path.Contains("/zones/records/add/example.com/TXT", StringComparison.Ordinal))
            {
                recordId = "99";
                return HttpStub.Json(HttpStatusCode.Created, """{"status":201}""");
            }

            if (request.Method == HttpMethod.Delete &&
                path.Contains("/zones/records/example.com/", StringComparison.Ordinal))
            {
                recordId = null;
                return HttpStub.Json(HttpStatusCode.OK, """{"status":200}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new EasyDnsDnsValidationPlugin(http);
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
            HttpStub.Json(status, $$"""{"status":{{(int)status}},"error":"invalid credentials"}"""));
        var plugin = new EasyDnsDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid credentials", ex.Message, StringComparison.Ordinal);
    }
}
