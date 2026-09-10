using System.Net;
using System.Net.Http;
using PowerDnsDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class PowerDnsDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["apiBaseUrl"] = "https://pdns.example:8081",
            ["apiKey"] = "secret"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_Succeeds()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            var path = NormalizePath(HttpStub.Path(request));
            Assert.Equal("secret", request.Headers.GetValues("X-API-Key").Single());

            if (request.Method == HttpMethod.Get &&
                path.Equals("/api/v1/servers/localhost/zones", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """[{"id":"example.com.","name":"example.com."}]""");
            }

            if (path.Equals("/api/v1/servers/localhost/zones/example.com.", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Get)
                {
                    if (!present)
                    {
                        return HttpStub.Json(
                            HttpStatusCode.OK,
                            """{"id":"example.com.","name":"example.com.","rrsets":[]}""");
                    }

                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"id":"example.com.","name":"example.com.","rrsets":[{"name":"_acme-challenge.www.example.com.","type":"TXT","ttl":60,"records":[{"content":"\"challenge-value\"","disabled":false}]}]}""");
                }

                if (request.Method == HttpMethod.Patch)
                {
                    var body = HttpStub.Body(request);
                    if (!present)
                    {
                        Assert.Contains("REPLACE", body, StringComparison.Ordinal);
                        Assert.Contains("challenge-value", body, StringComparison.Ordinal);
                        present = true;
                    }
                    else
                    {
                        Assert.Contains("DELETE", body, StringComparison.Ordinal);
                        present = false;
                    }

                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new PowerDnsDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound(HttpStatusCode status)
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(status, """{"error":"Unauthorized"}"""));
        var plugin = new PowerDnsDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains(((int)status).ToString(), ex.Message, StringComparison.Ordinal);
        Assert.Contains("Unauthorized", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentChallengeAsync_MissingZone_IsNotAuthFailure()
    {
        using var http = HttpStub.Client(request =>
        {
            var path = NormalizePath(HttpStub.Path(request));
            if (request.Method == HttpMethod.Get &&
                path.Equals("/api/v1/servers/localhost/zones", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, "[]");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)}");
        });

        var plugin = new PowerDnsDnsValidationPlugin(http);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        Assert.Contains("could not find a DNS zone", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("authentication/authorization failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path) =>
        path.EndsWith("/example.com", StringComparison.Ordinal) ? path + "." : path;
}
