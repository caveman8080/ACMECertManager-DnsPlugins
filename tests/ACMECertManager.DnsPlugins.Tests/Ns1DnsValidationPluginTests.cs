using System.Net;
using System.Net.Http;
using Ns1DnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class Ns1DnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiKey"] = "key"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutAnswersSubstring()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            var path = HttpStub.Path(request);

            if (request.Method == HttpMethod.Get &&
                path.Equals("/v1/zones", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """[{"zone":"example.com"}]""");
            }

            if (path.Equals("/v1/zones/example.com/_acme-challenge.www.example.com/TXT", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                {
                    if (!present)
                    {
                        return HttpStub.Json(HttpStatusCode.NotFound, """{"message":"record not found"}""");
                    }

                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"answers":[{"answer":["challenge-value"]}]}""");
                }

                if (request.Method == HttpMethod.Put)
                {
                    present = true;
                    return HttpStub.Json(HttpStatusCode.OK, """{"ok":true}""");
                }

                if (request.Method == HttpMethod.Delete)
                {
                    present = false;
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new Ns1DnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }
}
