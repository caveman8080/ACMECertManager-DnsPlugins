using System.Net;
using System.Net.Http;
using LoopiaDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class LoopiaDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["username"] = "user@loopiaapi",
            ["password"] = "pass"
        };

    [Fact]
    public async Task PresentAndCleanup_HappyPath_SucceedsWithoutRawOkSubstringOnHttpOnly()
    {
        string? recordId = null;
        using var http = HttpStub.Client(request =>
        {
            var body = HttpStub.Body(request);
            if (body.Contains("<methodName>getDomains</methodName>", StringComparison.Ordinal))
            {
                return HttpStub.Xml(
                    HttpStatusCode.OK,
                    """
                    <?xml version="1.0"?>
                    <methodResponse><params><param><value><array><data>
                    <value><struct><member><name>domain</name><value><string>example.com</string></value></member></struct></value>
                    </data></array></value></param></params></methodResponse>
                    """);
            }

            if (body.Contains("<methodName>getSubdomains</methodName>", StringComparison.Ordinal))
            {
                return HttpStub.Xml(
                    HttpStatusCode.OK,
                    """
                    <?xml version="1.0"?>
                    <methodResponse><params><param><value><array><data>
                    <value><string>@</string></value>
                    </data></array></value></param></params></methodResponse>
                    """);
            }

            if (body.Contains("<methodName>addSubdomain</methodName>", StringComparison.Ordinal))
            {
                return RpcOk();
            }

            if (body.Contains("<methodName>getZoneRecords</methodName>", StringComparison.Ordinal))
            {
                if (recordId is null)
                {
                    return HttpStub.Xml(
                        HttpStatusCode.OK,
                        """
                        <?xml version="1.0"?>
                        <methodResponse><params><param><value><array><data></data></array></value></param></params></methodResponse>
                        """);
                }

                return HttpStub.Xml(
                    HttpStatusCode.OK,
                    """
                    <?xml version="1.0"?>
                    <methodResponse><params><param><value><array><data>
                    <value><struct>
                      <member><name>type</name><value><string>TXT</string></value></member>
                      <member><name>rdata</name><value><string>challenge-value</string></value></member>
                      <member><name>record_id</name><value><int>99</int></value></member>
                    </struct></value>
                    </data></array></value></param></params></methodResponse>
                    """);
            }

            if (body.Contains("<methodName>addZoneRecord</methodName>", StringComparison.Ordinal))
            {
                recordId = "99";
                return RpcOk();
            }

            if (body.Contains("<methodName>removeZoneRecord</methodName>", StringComparison.Ordinal))
            {
                recordId = null;
                return RpcOk();
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new LoopiaDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();

        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.Created)]
    public async Task PresentChallengeAsync_Http2xxWithOk_Succeeds(HttpStatusCode status)
    {
        using var http = HttpStub.Client(request =>
        {
            var body = HttpStub.Body(request);
            if (body.Contains("<methodName>getDomains</methodName>", StringComparison.Ordinal))
            {
                return HttpStub.Xml(
                    HttpStatusCode.OK,
                    """
                    <?xml version="1.0"?>
                    <methodResponse><params><param><value><array><data>
                    <value><struct><member><name>domain</name><value><string>example.com</string></value></member></struct></value>
                    </data></array></value></param></params></methodResponse>
                    """);
            }

            if (body.Contains("<methodName>getSubdomains</methodName>", StringComparison.Ordinal) ||
                body.Contains("<methodName>getZoneRecords</methodName>", StringComparison.Ordinal))
            {
                return HttpStub.Xml(
                    HttpStatusCode.OK,
                    """
                    <?xml version="1.0"?>
                    <methodResponse><params><param><value><array><data></data></array></value></param></params></methodResponse>
                    """);
            }

            if (body.Contains("<methodName>addSubdomain</methodName>", StringComparison.Ordinal) ||
                body.Contains("<methodName>addZoneRecord</methodName>", StringComparison.Ordinal))
            {
                return RpcOk(status);
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {HttpStub.Url(request)} {body}");
        });

        var plugin = new LoopiaDnsValidationPlugin(http);
        await plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None);
    }

    [Fact]
    public async Task PresentChallengeAsync_AuthFailure_IsNotZoneNotFound()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Xml(
                HttpStatusCode.OK,
                """
                <?xml version="1.0"?>
                <methodResponse><params><param><value><string>AUTH_ERROR</string></value></param></params></methodResponse>
                """));
        var plugin = new LoopiaDnsValidationPlugin(http);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));

        HttpStub.AssertAuthFailure(ex);
        Assert.Contains("AUTH_ERROR", ex.Message, StringComparison.Ordinal);
    }

    private static HttpResponseMessage RpcOk(HttpStatusCode status = HttpStatusCode.OK) =>
        HttpStub.Xml(
            status,
            """
            <?xml version="1.0"?>
            <methodResponse><params><param><value><string>OK</string></value></param></params></methodResponse>
            """);
}
