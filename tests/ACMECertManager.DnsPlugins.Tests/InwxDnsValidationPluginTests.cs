using System.Net;
using System.Net.Http;
using InwxDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class InwxDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["username"] = "user",
            ["password"] = "pass"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutCommandCompletedSubstring()
    {
        string? recordId = null;
        using var http = HttpStub.Client(request =>
        {
            var body = HttpStub.Body(request);
            if (body.Contains("account.login", StringComparison.Ordinal))
            {
                var response = HttpStub.Json(HttpStatusCode.OK, """{"code":1000,"resData":{}}""");
                response.Headers.TryAddWithoutValidation("Set-Cookie", "domrobot=sess");
                return response;
            }

            if (body.Contains("nameserver.list", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"code":1000,"resData":{"domains":[{"domain":"example.com"}]}}""");
            }

            if (body.Contains("nameserver.info", StringComparison.Ordinal))
            {
                if (recordId is null)
                {
                    return HttpStub.Json(HttpStatusCode.OK, """{"code":1000,"resData":{"record":[]}}""");
                }

                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"code":1000,"resData":{"record":[{"id":99,"type":"TXT","name":"_acme-challenge.www","content":"challenge-value"}]}}""");
            }

            if (body.Contains("nameserver.createRecord", StringComparison.Ordinal))
            {
                recordId = "99";
                return HttpStub.Json(HttpStatusCode.OK, """{"code":1000}""");
            }

            if (body.Contains("nameserver.deleteRecord", StringComparison.Ordinal))
            {
                recordId = null;
                return HttpStub.Json(HttpStatusCode.OK, """{"code":1000}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new InwxDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.Created)]
    public async Task PresentChallengeAsync_Http2xxWithCode1000_Succeeds(HttpStatusCode status)
    {
        using var http = HttpStub.Client(request =>
        {
            var body = HttpStub.Body(request);
            if (body.Contains("account.login", StringComparison.Ordinal))
            {
                var response = HttpStub.Json(HttpStatusCode.OK, """{"code":1000,"resData":{}}""");
                response.Headers.TryAddWithoutValidation("Set-Cookie", "domrobot=sess");
                return response;
            }

            if (body.Contains("nameserver.list", StringComparison.Ordinal))
            {
                return HttpStub.Json(
                    HttpStatusCode.OK,
                    """{"code":1000,"resData":{"domains":[{"domain":"example.com"}]}}""");
            }

            if (body.Contains("nameserver.info", StringComparison.Ordinal))
            {
                return HttpStub.Json(HttpStatusCode.OK, """{"code":1000,"resData":{"record":[]}}""");
            }

            if (body.Contains("nameserver.createRecord", StringComparison.Ordinal))
            {
                return HttpStub.Json(status, """{"code":1000}""");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new InwxDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Fact]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(HttpStatusCode.OK, """{"code":2200,"msg":"Authentication error"}"""));
        var plugin = new InwxDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("2200", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Authentication error", ex.Message, StringComparison.Ordinal);
    }
}
