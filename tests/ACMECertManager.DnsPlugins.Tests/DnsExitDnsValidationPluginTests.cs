using System.Net;
using System.Net.Http;
using DnsExitDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class DnsExitDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "exit-key"
        };

    [Fact]
    public async Task PresentAndCleanup_WalksCandidatesUntilCodeZero()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("exit-key", request.Headers.GetValues("apikey").Single());
            var body = HttpStub.Body(request);

            if (!body.Contains("\"domain\":\"example.com\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"code":1,"message":"not this zone"}""");
            }
            if (body.Contains("\"add\":", StringComparison.Ordinal))
            {
                Assert.Contains("\"type\":\"TXT\"", body, StringComparison.Ordinal);
                Assert.Contains("_acme-challenge.www", body, StringComparison.Ordinal);
                Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                present = true;
                return HttpStub.Json(HttpStatusCode.OK, """{"code":0,"message":"Success"}""");
            }

            Assert.Contains("\"delete\":", body, StringComparison.Ordinal);
            present = false;
            return HttpStub.Json(HttpStatusCode.OK, """{"code":0,"message":"Success"}""");
        });

        var plugin = new DnsExitDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();
        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }
}
