using System.Net;
using System.Net.Http;
using NameSiloDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class NameSiloDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "key"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_Succeeds()
    {
        string? recordId = null;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);
            var url = HttpStub.Url(request);

            if (path.Contains("/listDomains", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"reply":{"code":300,"domains":["example.com"]}}""");
            }

            if (path.Contains("/dnsListRecords", StringComparison.Ordinal))
            {
                if (recordId is null)
                {
                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"reply":{"code":300,"resource_record":[]}}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"reply":{"code":300,"resource_record":[{"record_id":"99","type":"TXT","host":"_acme-challenge.www.example.com","value":"challenge-value"}]}}""");
            }

            if (path.Contains("/dnsAddRecord", StringComparison.Ordinal))
            {
                recordId = "99";
                return HttpStub.Json(HttpStatusCode.OK, """{"reply":{"code":300,"record_id":"99"}}""");
            }

            if (path.Contains("/dnsDeleteRecord", StringComparison.Ordinal))
            {
                Assert.Contains("rrid=99", url, StringComparison.Ordinal);
                recordId = null;
                return HttpStub.Json(HttpStatusCode.OK, """{"reply":{"code":300}}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {url}");
        });

        var plugin = new NameSiloDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.Created)]
    public async Task PresentChallengeAsync_Http2xxWithCode300_Succeeds(HttpStatusCode status)
    {
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (path.Contains("/listDomains", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"reply":{"code":300,"domains":["example.com"]}}""");
            }

            if (path.Contains("/dnsListRecords", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"reply":{"code":300,"resource_record":[]}}""");
            }

            if (path.Contains("/dnsAddRecord", StringComparison.Ordinal))
            {
                return HttpStub.Json(status, """{"reply":{"code":300}}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new NameSiloDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Fact]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(HttpStatusCode.OK, """{"reply":{"code":110,"detail":"Invalid API Key"}}"""));
        var plugin = new NameSiloDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("110", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Invalid API Key", ex.Message, StringComparison.Ordinal);
    }
}
