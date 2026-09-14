using System.Net;
using System.Net.Http;
using AliyunDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class AliyunDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["accessKeyId"] = "testid",
            ["accessKeySecret"] = "testsecret"
        };

    [Fact]
    public void PercentEncode_LeavesTilde_EncodesStarAndPlus()
    {
        Assert.Equal("~", AliyunDnsValidationPlugin.PercentEncode("~"));
        Assert.Equal("%2A", AliyunDnsValidationPlugin.PercentEncode("*"));
        Assert.Equal("%2B", AliyunDnsValidationPlugin.PercentEncode("+"));
        Assert.Equal("%20", AliyunDnsValidationPlugin.PercentEncode(" "));
    }

    [Fact]
    public void SignUrl_UsesHmacSha1QuerySignature()
    {
        var query = new Dictionary<string, string>
        {
            ["AccessKeyId"] = "testid",
            ["Action"] = "DescribeDomains",
            ["Format"] = "json",
            ["SignatureMethod"] = "HMAC-SHA1",
            ["SignatureNonce"] = "nonce",
            ["SignatureVersion"] = "1.0",
            ["Timestamp"] = "2016-03-29T03:33:18Z",
            ["Version"] = "2015-01-09"
        };

        var url = AliyunDnsValidationPlugin.SignUrl("testsecret", query);
        Assert.Contains("https://alidns.aliyuncs.com/?", url, StringComparison.Ordinal);
        Assert.Contains("Action=DescribeDomains", url, StringComparison.Ordinal);
        Assert.Contains("Signature=", url, StringComparison.Ordinal);
        Assert.DoesNotContain("Signature=testsecret", url, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PresentAndCleanup_HappyPath()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            var url = HttpStub.Url(request);
            Assert.Contains("Signature=", url, StringComparison.Ordinal);
            Assert.Contains("AccessKeyId=testid", url, StringComparison.Ordinal);

            if (url.Contains("Action=DescribeDomainRecords", StringComparison.Ordinal) &&
                !url.Contains("RRKeyWord=", StringComparison.Ordinal))
            {
                return url.Contains("DomainName=example.com", StringComparison.Ordinal)
                    ? HttpStub.Json(HttpStatusCode.OK, """{"PageNumber":1,"TotalCount":1,"DomainRecords":{"Record":[]}}""")
                    : HttpStub.Json(HttpStatusCode.OK, """{"Code":"InvalidDomainName.NoExist","Message":"missing"}""");
            }

            if (url.Contains("Action=DescribeDomainRecords", StringComparison.Ordinal) &&
                url.Contains("RRKeyWord=", StringComparison.Ordinal))
            {
                return present
                    ? HttpStub.Json(
                        HttpStatusCode.OK,
                        """{"PageNumber":1,"DomainRecords":{"Record":[{"RR":"_acme-challenge.www","Type":"TXT","Value":"challenge-value","RecordId":"rec-1"}]}}""")
                    : HttpStub.Json(HttpStatusCode.OK, """{"PageNumber":1,"DomainRecords":{"Record":[]}}""");
            }

            if (url.Contains("Action=AddDomainRecord", StringComparison.Ordinal))
            {
                Assert.Contains("Type=TXT", url, StringComparison.Ordinal);
                Assert.Contains("Value=challenge-value", url, StringComparison.Ordinal);
                present = true;
                return HttpStub.Json(HttpStatusCode.OK, """{"RecordId":"rec-1","RequestId":"x"}""");
            }

            if (url.Contains("Action=DeleteDomainRecord", StringComparison.Ordinal))
            {
                Assert.Contains("RecordId=rec-1", url, StringComparison.Ordinal);
                present = false;
                return HttpStub.Json(HttpStatusCode.OK, """{"RequestId":"x"}""");
            }

            throw new InvalidOperationException($"Unexpected request: {url}");
        });

        var plugin = new AliyunDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();
        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }

    [Fact]
    public async Task Present_AuthFailure_IsNotMissingZone()
    {
        using var http = HttpStub.Client(_ =>
            HttpStub.Json(HttpStatusCode.OK, """{"Code":"InvalidAccessKeyId.NotFound","Message":"bad key"}"""));
        var plugin = new AliyunDnsValidationPlugin(http);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => plugin.PresentChallengeAsync(HttpStub.Challenge(), Credentials, CancellationToken.None));
        HttpStub.AssertAuthFailure(ex);
    }
}
