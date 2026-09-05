using ACMECertManager;
using System.Globalization;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Xml.Linq;

namespace LoopiaDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class LoopiaDnsValidationPlugin : IDnsValidationPlugin
{
    private const string DefaultApiUrl = "https://api.loopia.se/RPCSERV";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public LoopiaDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public LoopiaDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "loopia",
        DisplayName = "Loopia",
        Description = "DNS-01 via the Loopia XML-RPC HTTP API using username and password."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "username",
            Label = "Username",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "Loopia API username (LOOPIA_User)"
        },
        new DnsCredentialField
        {
            Name = "password",
            Label = "Password",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Loopia API password (LOOPIA_Password)"
        },
        new DnsCredentialField
        {
            Name = "apiUrl",
            Label = "API URL",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default https://api.loopia.se/RPCSERV"
        },
        new DnsCredentialField
        {
            Name = "propagationSeconds",
            Label = "DNS propagation wait (seconds)",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default 30"
        }
    ];

    public async Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var username = GetRequired(credentials, "username");
        var password = GetRequired(credentials, "password");
        var apiUrl = GetApiUrl(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiUrl, username, password, recordName, cancellationToken).ConfigureAwait(false);
        var relative = ToHost(GetRelativeName(recordName, zone));

        if (await FindRecordIdAsync(apiUrl, username, password, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        await EnsureSubdomainAsync(apiUrl, username, password, zone, relative, cancellationToken).ConfigureAwait(false);

        var (status, body) = await CallAsync(
            apiUrl,
            "addZoneRecord",
            [
                username,
                password,
                zone,
                relative,
                new Dictionary<string, object>
                {
                    ["type"] = "TXT",
                    ["priority"] = 0,
                    ["ttl"] = 300,
                    ["rdata"] = request.TxtValue
                }
            ],
            cancellationToken).ConfigureAwait(false);

        if (IsOk(status, body) || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Loopia add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var username = GetRequired(credentials, "username");
        var password = GetRequired(credentials, "password");
        var apiUrl = GetApiUrl(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiUrl, username, password, recordName, cancellationToken).ConfigureAwait(false);
        var relative = ToHost(GetRelativeName(recordName, zone));
        var recordId = await FindRecordIdAsync(apiUrl, username, password, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await CallAsync(
            apiUrl,
            "removeZoneRecord",
            [username, password, zone, relative, int.TryParse(recordId, out var id) ? id : recordId],
            cancellationToken).ConfigureAwait(false);

        if (IsOk(status, body) || status is 404 || IsNotFound(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Loopia delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string apiUrl,
        string username,
        string password,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await CallAsync(
            apiUrl,
            "getDomains",
            [username, password],
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Loopia list domains failed ({status}): {TrimBody(body)}");
        }

        var names = new HashSet<string>(CollectStrings(body).Select(NormalizeHost), StringComparer.Ordinal);
        foreach (var candidate in CandidateZones(recordName))
        {
            if (names.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"Loopia could not find a DNS zone for '{recordName}'.");
    }

    private async Task EnsureSubdomainAsync(
        string apiUrl,
        string username,
        string password,
        string zone,
        string relative,
        CancellationToken cancellationToken)
    {
        var (listStatus, listBody) = await CallAsync(
            apiUrl,
            "getSubdomains",
            [username, password, zone],
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(listStatus, listBody);
        var existing = new HashSet<string>(CollectStrings(listBody).Select(NormalizeHost), StringComparer.Ordinal);
        var wanted = NormalizeHost(relative == "@" ? "@" : relative);
        if (existing.Contains(wanted) || existing.Contains(relative) || (relative == "@" && existing.Contains("")))
        {
            return;
        }

        var (status, body) = await CallAsync(
            apiUrl,
            "addSubdomain",
            [username, password, zone, relative],
            cancellationToken).ConfigureAwait(false);

        if (IsOk(status, body) || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Loopia add subdomain failed ({status}): {TrimBody(body)}");
    }

    private async Task<string?> FindRecordIdAsync(
        string apiUrl,
        string username,
        string password,
        string zone,
        string relative,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await CallAsync(
            apiUrl,
            "getZoneRecords",
            [username, password, zone, relative],
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body);
        if (IsNotFound(body))
        {
            return null;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Loopia list records failed ({status}): {TrimBody(body)}");
        }

        foreach (var record in ParseStructs(body))
        {
            var type = record.GetValueOrDefault("type");
            var rdata = UnquoteTxt(record.GetValueOrDefault("rdata") ?? string.Empty);
            var id = record.GetValueOrDefault("record_id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(rdata, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body)> CallAsync(
        string apiUrl,
        string method,
        IReadOnlyList<object> args,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, apiUrl);
        request.Headers.TryAddWithoutValidation("Accept", "text/xml, application/xml");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-LoopiaDnsPlugin");
        request.Content = new StringContent(BuildMethodCall(method, args), Encoding.UTF8, "text/xml");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (status is 401 or 403 ||
            ContainsStatus(body, "AUTH_ERROR") ||
            ContainsStatus(body, "AUTH_ERROR_IP_RESTRICTED") ||
            ContainsStatus(body, "AUTHENTICATION_ERROR"))
        {
            throw new InvalidOperationException(
                $"Loopia authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsOk(int status, string body)
    {
        if (status is < 200 or >= 300)
        {
            return false;
        }

        var values = CollectStrings(body).ToList();
        return values.Exists(value => string.Equals(value, "OK", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsAlreadyExists(string body) =>
        ContainsStatus(body, "DOMAIN_OCCUPIED") ||
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase);

    private static bool IsNotFound(string body) =>
        ContainsStatus(body, "UNKNOWN_ERROR") && body.Contains("not found", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsStatus(string body, string expected)
    {
        foreach (var value in CollectStrings(body))
        {
            if (string.Equals(value, expected, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string BuildMethodCall(string method, IReadOnlyList<object> args)
    {
        var sb = new StringBuilder();
        sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        sb.Append("<methodCall><methodName>").Append(XmlEscape(method)).Append("</methodName><params>");
        foreach (var arg in args)
        {
            sb.Append("<param><value>");
            AppendValue(sb, arg);
            sb.Append("</value></param>");
        }

        sb.Append("</params></methodCall>");
        return sb.ToString();
    }

    private static void AppendValue(StringBuilder sb, object value)
    {
        switch (value)
        {
            case int number:
                sb.Append("<int>").Append(number.ToString(CultureInfo.InvariantCulture)).Append("</int>");
                break;
            case Dictionary<string, object> members:
                sb.Append("<struct>");
                foreach (var (name, member) in members)
                {
                    sb.Append("<member><name>").Append(XmlEscape(name)).Append("</name><value>");
                    AppendValue(sb, member);
                    sb.Append("</value></member>");
                }

                sb.Append("</struct>");
                break;
            default:
                sb.Append("<string>").Append(XmlEscape(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty)).Append("</string>");
                break;
        }
    }

    private static IEnumerable<string> CollectStrings(string xml)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (System.Xml.XmlException)
        {
            yield break;
        }

        foreach (var element in doc.Descendants())
        {
            if (element.Name.LocalName is "string" or "int" or "i4" && !string.IsNullOrWhiteSpace(element.Value))
            {
                yield return element.Value.Trim();
            }
        }
    }

    private static List<Dictionary<string, string>> ParseStructs(string xml)
    {
        var result = new List<Dictionary<string, string>>();
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (System.Xml.XmlException)
        {
            return result;
        }

        foreach (var structElement in doc.Descendants().Where(e => e.Name.LocalName == "struct"))
        {
            var record = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var member in structElement.Elements().Where(e => e.Name.LocalName == "member"))
            {
                var name = member.Elements().FirstOrDefault(e => e.Name.LocalName == "name")?.Value;
                var value = member.Descendants().FirstOrDefault(e => e.Name.LocalName is "string" or "int" or "i4")?.Value;
                if (!string.IsNullOrWhiteSpace(name) && value is not null)
                {
                    record[name] = value.Trim();
                }
            }

            if (record.Count > 0)
            {
                result.Add(record);
            }
        }

        return result;
    }

    private static string XmlEscape(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);

    private static string UnquoteTxt(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
        {
            return trimmed[1..^1];
        }

        return trimmed;
    }

    private static IEnumerable<string> CandidateZones(string fqdn)
    {
        var labels = NormalizeHost(fqdn).Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < labels.Length - 1; i++)
        {
            yield return string.Join('.', labels.Skip(i));
        }
    }

    private static string GetRelativeName(string fqdn, string zone)
    {
        fqdn = NormalizeHost(fqdn);
        zone = NormalizeHost(zone);
        if (fqdn == zone)
        {
            return "";
        }

        if (fqdn.EndsWith("." + zone, StringComparison.Ordinal))
        {
            return fqdn[..^(zone.Length + 1)];
        }

        throw new InvalidOperationException($"Record '{fqdn}' is not in zone '{zone}'.");
    }

    private static string ToHost(string relative) => string.IsNullOrEmpty(relative) ? "@" : relative;

    private static string GetApiUrl(IReadOnlyDictionary<string, string> credentials)
    {
        if (credentials.TryGetValue("apiUrl", out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value.Trim();
        }

        return DefaultApiUrl;
    }

    private static string GetRequired(IReadOnlyDictionary<string, string> credentials, string key)
    {
        if (!credentials.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Missing required credential '{key}'.");
        }

        return value.Trim();
    }

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }
}
