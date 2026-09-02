using System.Net;
using System.Net.Http;
using MythicBeastsDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class MythicBeastsDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "key",
            ["apiSecret"] = "secret"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutRecordsAddedSubstring()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            var url = HttpStub.Url(request);
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Post &&
                url.StartsWith("https://auth.mythic-beasts.com/login", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"access_token":"access-token"}""");
            }

            if (request.Method == HttpMethod.Get &&
                path.Equals("/dns/v2/zones", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"zones":["example.com"]}""");
            }

            if (path.Equals("/dns/v2/zones/example.com/records/_acme-challenge.www/TXT", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                {
                    if (!present)
                    {
                        return HttpStub.Json(HttpStatusCode.NotFound, """{"error":"no such record"}""");
                    }

                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"records":[{"type":"TXT","host":"_acme-challenge.www","data":"challenge-value"}]}""");
                }

                if (request.Method == HttpMethod.Post)
                {
                    present = true;
                    return HttpStub.Json(HttpStatusCode.OK, """{"ok":true}""");
                }

                if (request.Method == HttpMethod.Delete)
                {
                    present = false;
                    return HttpStub.Json(HttpStatusCode.OK, """{"ok":true}""");
                }
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {url}");
        });

        var plugin = new MythicBeastsDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }
}
