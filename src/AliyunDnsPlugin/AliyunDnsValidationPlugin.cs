using ACMECertManager;
using System.Globalization;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AliyunDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class AliyunDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://alidns.aliyuncs.com/";
    private const string ApiVersion = "2015-01-09";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public AliyunDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public AliyunDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "aliyun",
        DisplayName = "Aliyun (Alibaba Cloud DNS)",
        Description = "DNS-01 via the Alibaba Cloud DNS HTTP RPC API using an AccessKey ID and AccessKey secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "accessKeyId",
            Label = "AccessKey ID",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Aliyun AccessKey ID (Ali_Key)"
        },
        new DnsCredentialField
        {
            Name = "accessKeySecret",
            Label = "AccessKey Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Aliyun AccessKey secret (Ali_Secret)"
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
        var accessKeyId = GetRequired(credentials, "accessKeyId");
        var accessKeySecret = GetRequired(credentials, "accessKeySecret");
        var recordName = ToPunycode(request.RecordName);
        var zone = await ResolveZoneAsync(accessKeyId, accessKeySecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        if (string.IsNullOrEmpty(relative))
        {
            relative = "@";
        }

        var existingId = await FindRecordIdAsync(
            accessKeyId,
            accessKeySecret,
            zone,
            relative,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var query = BaseQuery(accessKeyId);
        query["Action"] = "AddDomainRecord";
        query["DomainName"] = zone;
        query["RR"] = relative;
        query["Type"] = "TXT";
        query["Value"] = request.TxtValue;

        var (status, body) = await GetAsync(accessKeySecret, query, cancellationToken).ConfigureAwait(false);
        ThrowIfAuthFailed(status, body);
        if (!IsApiSuccess(body) && !IsAlreadyExists(body))
        {
            throw new InvalidOperationException($"Aliyun add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var accessKeyId = GetRequired(credentials, "accessKeyId");
        var accessKeySecret = GetRequired(credentials, "accessKeySecret");
        var recordName = ToPunycode(request.RecordName);
        var zone = await ResolveZoneAsync(accessKeyId, accessKeySecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        if (string.IsNullOrEmpty(relative))
        {
            relative = "@";
        }

        var recordId = await FindRecordIdAsync(
            accessKeyId,
            accessKeySecret,
            zone,
            relative,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var query = BaseQuery(accessKeyId);
        query["Action"] = "DeleteDomainRecord";
        query["RecordId"] = recordId;

        var (status, body) = await GetAsync(accessKeySecret, query, cancellationToken).ConfigureAwait(false);
        ThrowIfAuthFailed(status, body);
        if (!IsApiSuccess(body))
        {
            throw new InvalidOperationException($"Aliyun delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private async Task<string> ResolveZoneAsync(
        string accessKeyId,
        string accessKeySecret,
        string recordName,
        CancellationToken cancellationToken)
    {
        string lastBody = string.Empty;
        int lastStatus = 0;

        foreach (var candidate in CandidateZones(recordName))
        {
            var query = BaseQuery(accessKeyId);
            query["Action"] = "DescribeDomainRecords";
            query["DomainName"] = candidate;

            var (status, body) = await GetAsync(accessKeySecret, query, cancellationToken).ConfigureAwait(false);
            lastStatus = status;
            lastBody = body;
            ThrowIfAuthFailed(status, body);

            if (IsZoneMatch(body))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            $"Aliyun could not find a zone for '{recordName}' ({lastStatus}): {TrimBody(lastBody)}");
    }

    private async Task<string?> FindRecordIdAsync(
        string accessKeyId,
        string accessKeySecret,
        string zone,
        string relative,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var query = BaseQuery(accessKeyId);
        query["Action"] = "DescribeDomainRecords";
        query["DomainName"] = zone;
        query["RRKeyWord"] = relative;
        query["TypeKeyWord"] = "TXT";

        var (status, body) = await GetAsync(accessKeySecret, query, cancellationToken).ConfigureAwait(false);
        ThrowIfAuthFailed(status, body);
        if (!IsApiSuccess(body))
        {
            return null;
        }

        foreach (var record in EnumerateRecords(body))
        {
            var rr = ReadString(record, "RR") ?? string.Empty;
            var type = ReadString(record, "Type") ?? string.Empty;
            var value = ReadString(record, "Value") ?? string.Empty;
            var id = ReadString(record, "RecordId");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(rr, relative, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(value, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body)> GetAsync(
        string accessKeySecret,
        Dictionary<string, string> query,
        CancellationToken cancellationToken)
    {
        var url = SignUrl(accessKeySecret, query);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-AliyunDnsPlugin");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    internal static string SignUrl(string accessKeySecret, Dictionary<string, string> query)
    {
        var canonical = string.Join(
            "&",
            query
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{PercentEncode(pair.Key)}={PercentEncode(pair.Value)}"));
        var stringToSign = $"GET&{PercentEncode("/")}&{PercentEncode(canonical)}";
        var signature = SignHmacSha1(accessKeySecret + "&", stringToSign);
        return $"{ApiBase}?{canonical}&Signature={PercentEncode(signature)}";
    }

    internal static string PercentEncode(string value)
    {
        var encoded = Uri.EscapeDataString(value);
        return encoded
            .Replace("%7E", "~", StringComparison.Ordinal)
            .Replace("%7e", "~", StringComparison.Ordinal);
    }

    private static string SignHmacSha1(string key, string data)
    {
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
    }

    private static Dictionary<string, string> BaseQuery(string accessKeyId) =>
        new()
        {
            ["AccessKeyId"] = accessKeyId,
            ["Format"] = "json",
            ["SignatureMethod"] = "HMAC-SHA1",
            ["SignatureNonce"] = Guid.NewGuid().ToString("N"),
            ["SignatureVersion"] = "1.0",
            ["Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["Version"] = ApiVersion
        };

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (status is 401 or 403 || IsAuthFailure(body))
        {
            throw new InvalidOperationException(
                $"Aliyun authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsAuthFailure(string body)
    {
        var code = ReadErrorCode(body);
        if (string.IsNullOrEmpty(code))
        {
            return false;
        }

        return code.Contains("InvalidAccessKeyId", StringComparison.OrdinalIgnoreCase) ||
               code.Contains("SignatureDoesNotMatch", StringComparison.OrdinalIgnoreCase) ||
               code.Contains("IncompleteSignature", StringComparison.OrdinalIgnoreCase) ||
               code.Contains("Forbidden", StringComparison.OrdinalIgnoreCase) ||
               code.Contains("InvalidAccessKeySecret", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsApiSuccess(string body)
    {
        var code = ReadErrorCode(body);
        return string.IsNullOrEmpty(code) ||
               string.Equals(code, "OK", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAlreadyExists(string body)
    {
        var code = ReadErrorCode(body) ?? string.Empty;
        return code.Contains("DomainRecordDuplicate", StringComparison.OrdinalIgnoreCase) ||
               body.Contains("already exists", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsZoneMatch(string body)
    {
        if (!IsApiSuccess(body))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("PageNumber", out _) ||
                   doc.RootElement.TryGetProperty("DomainRecords", out _);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string? ReadErrorCode(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return ReadString(doc.RootElement, "Code");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static IEnumerable<JsonElement> EnumerateRecords(string body)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            yield break;
        }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("DomainRecords", out var domainRecords) ||
                domainRecords.ValueKind != JsonValueKind.Object ||
                !domainRecords.TryGetProperty("Record", out var records))
            {
                yield break;
            }

            if (records.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in records.EnumerateArray())
                {
                    yield return record.Clone();
                }
            }
            else if (records.ValueKind == JsonValueKind.Object)
            {
                yield return records.Clone();
            }
        }
    }

    private static string? ReadString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
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
            return string.Empty;
        }

        if (fqdn.EndsWith("." + zone, StringComparison.Ordinal))
        {
            return fqdn[..^(zone.Length + 1)];
        }

        throw new InvalidOperationException($"Record '{fqdn}' is not in zone '{zone}'.");
    }

    private static string ToPunycode(string host)
    {
        var normalized = NormalizeHost(host);
        try
        {
            return new System.Globalization.IdnMapping().GetAscii(normalized);
        }
        catch (ArgumentException)
        {
            return normalized;
        }
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
