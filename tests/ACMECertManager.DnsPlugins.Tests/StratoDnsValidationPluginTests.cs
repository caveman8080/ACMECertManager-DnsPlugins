using System.Net;
using System.Net.Http;
using System.Text;
using StratoDnsPlugin;

namespace ACMECertManager.DnsPlugins.Tests;

public sealed class StratoDnsValidationPluginTests
{
    private static readonly IReadOnlyDictionary<string, string> Credentials =
        new Dictionary<string, string>
        {
            ["username"] = "12345678",
            ["password"] = "secret"
        };

    [Fact]
    public void ParseRecords_ReadsTxtBlocks()
    {
        const string html = """
            <div class="txt-record-tmpl">
              <input name="prefix" value="_acme-challenge" />
              <select name="type"><option selected>TXT</option></select>
              <textarea name="value">keep-me</textarea>
            </div>
            <div class="txt-record-tmpl">
              <input name="prefix" value="www" />
              <select name="type"><option selected>CNAME</option></select>
              <textarea name="value">example.com</textarea>
            </div>
            """;

        var records = StratoDnsValidationPlugin.ParseRecords(html);
        Assert.Equal(2, records.Count);
        Assert.Equal("_acme-challenge", records[0].Prefix);
        Assert.Equal("TXT", records[0].Type);
        Assert.Equal("keep-me", records[0].Value);
        Assert.Equal("CNAME", records[1].Type);
    }

    [Fact]
    public async Task PresentAndCleanup_PostsFullRecordList()
    {
        var present = false;
        using var http = HttpStub.Client(request =>
        {
            var url = HttpStub.Url(request);
            var body = HttpStub.Body(request);

            if (request.Method == HttpMethod.Get && !url.Contains("sessionID=", StringComparison.Ordinal))
            {
                return Html(HttpStatusCode.OK, "<html>login</html>");
            }

            if (request.Method == HttpMethod.Post && body.Contains("action_customer_login.x", StringComparison.Ordinal))
            {
                Assert.Contains("identifier=12345678", body, StringComparison.Ordinal);
                var response = Html(HttpStatusCode.OK, "<html>ok</html>");
                response.Headers.Location = new Uri("https://www.strato.de/apps/CustomerService?sessionID=sid-1");
                return response;
            }

            if (request.Method == HttpMethod.Get && url.Contains("kds_CustomerEntryPage", StringComparison.Ordinal))
            {
                return Html(
                    HttpStatusCode.OK,
                    """<table id="package_list"><tr><td>example.com</td><a href="?cID=42">pkg</a></tr></table>""");
            }

            if (request.Method == HttpMethod.Get && url.Contains("action_show_txt_records", StringComparison.Ordinal))
            {
                var existing = present
                    ? """
                      <div class="txt-record-tmpl">
                        <input name="prefix" value="_acme-challenge.www" />
                        <select name="type"><option selected>TXT</option></select>
                        <textarea name="value">challenge-value</textarea>
                      </div>
                      """
                    : """
                      <div class="txt-record-tmpl">
                        <input name="prefix" value="www" />
                        <select name="type"><option selected>CNAME</option></select>
                        <textarea name="value">example.com</textarea>
                      </div>
                      """;
                return Html(HttpStatusCode.OK, existing);
            }

            if (request.Method == HttpMethod.Post && body.Contains("action_change_txt_records", StringComparison.Ordinal))
            {
                if (body.Contains("challenge-value", StringComparison.Ordinal) &&
                    body.Contains("prefix=_acme-challenge.www", StringComparison.Ordinal))
                {
                    present = true;
                }
                else
                {
                    present = false;
                }

                return Html(HttpStatusCode.OK, "<html>saved</html>");
            }

            throw new InvalidOperationException($"Unexpected request: {request.Method} {url} {body}");
        });

        var plugin = new StratoDnsValidationPlugin(http);
        var challenge = HttpStub.Challenge();
        await plugin.PresentChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.True(present);
        await plugin.CleanupChallengeAsync(challenge, Credentials, CancellationToken.None);
        Assert.False(present);
    }

    private static HttpResponseMessage Html(HttpStatusCode status, string body) =>
        new(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/html")
        };
}
