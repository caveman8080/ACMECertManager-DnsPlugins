using System.Net;
using System.Net.Http;
using NetcupDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class NetcupDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["customerNumber"] = "12345",
            ["apiKey"] = "key",
            ["apiPassword"] = "pw"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_Succeeds()
    {
        string? recordId = null;
        using var http = HttpStub.Client(request =>
        {
            var body = HttpStub.Body(request);
            if (body.Contains("\"login\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"status":"success","statuscode":2000,"responsedata":{"apisessionid":"sid"}}""");
            }

            if (body.Contains("\"logout\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","statuscode":2000}""");
            }

            if (body.Contains("\"infoDnsRecords\"", StringComparison.Ordinal))
            {
                if (!body.Contains("\"example.com\"", StringComparison.Ordinal))
                {
                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"error","statuscode":5028,"shortmessage":"Zone not found"}""");
                }

                if (recordId is null)
                {
                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"success","statuscode":2000,"responsedata":{"dnsrecords":[]}}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"status":"success","statuscode":2000,"responsedata":{"dnsrecords":[{"id":"99","hostname":"_acme-challenge.www","type":"TXT","destination":"challenge-value"}]}}""");
            }

            if (body.Contains("\"updateDnsRecords\"", StringComparison.Ordinal))
            {
                if (body.Contains("\"deleterecord\":true", StringComparison.Ordinal) ||
                    body.Contains("\"deleterecord\": true", StringComparison.Ordinal))
                {
                    recordId = null;
                    return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","statuscode":2000}""");
                }

                recordId = "99";
                return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","statuscode":2000}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new NetcupDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }

    [Fact]
    public async Task PresentChallengeAsync_Http2xxWithApiSuccess_Succeeds()
    {
        using var http = HttpStub.Client(request =>
        {
            var body = HttpStub.Body(request);
            if (body.Contains("\"login\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"status":"success","statuscode":2000,"responsedata":{"apisessionid":"sid"}}""");
            }

            if (body.Contains("\"logout\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"status":"success","statuscode":2000}""");
            }

            if (body.Contains("\"infoDnsRecords\"", StringComparison.Ordinal))
            {
                if (!body.Contains("\"example.com\"", StringComparison.Ordinal))
                {
                    return HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"status":"error","statuscode":5028,"shortmessage":"Zone not found"}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"status":"success","statuscode":2000,"responsedata":{"dnsrecords":[]}}""");
            }

            if (body.Contains("\"updateDnsRecords\"", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.Created, """{"status":"success","statuscode":2000}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new NetcupDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Fact]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(
                HttpStatusCode.OK,
                """{"status":"error","statuscode":4012,"shortmessage":"Unauthorized.","longmessage":"Invalid API key."}"""));
        var plugin = new NetcupDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("4012", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Invalid API key", ex.Message, StringComparison.Ordinal);
    }
}
