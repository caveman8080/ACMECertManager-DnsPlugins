using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ExoscaleDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class ExoscaleDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api-ch-gva-2.exoscale.com/v2";
    private const int SignatureTtlSeconds = 600;
    private const int TxtTtl = 120;
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public ExoscaleDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public ExoscaleDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "exoscale",
        DisplayName = "Exoscale DNS",
        Description = "DNS-01 via the Exoscale DNS HTTP API using an API key and secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Exoscale API key (EXOSCALE_API_KEY)"
        },
        new DnsCredentialField
        {
            Name = "apiSecret",
            Label = "API Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Exoscale API secret (EXOSCALE_API_SECRET)"
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
        var apiKey = GetRequired(credentials, "apiKey");
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone.Name);

        if (await FindRecordIdAsync(apiKey, apiSecret, zone.Id, relative, recordName, request.TxtValue, cancellationToken)
                .ConfigureAwait(false) is not null)
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            name = relative,
            type = "TXT",
            content = request.TxtValue,
            ttl = TxtTtl
        });
        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/dns-domain/{Uri.EscapeDataString(zone.Id)}/record",
            apiKey,
            apiSecret,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || IsAlreadyExists(body))
        {
            return;
        }

        throw new InvalidOperationException($"Exoscale add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone.Name);
        var recordId = await FindRecordIdAsync(
            apiKey,
            apiSecret,
            zone.Id,
            relative,
            recordName,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/dns-domain/{Uri.EscapeDataString(zone.Id)}/record/{Uri.EscapeDataString(recordId)}",
            apiKey,
            apiSecret,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || status is 404)
        {
            return;
        }

        throw new InvalidOperationException($"Exoscale delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<Zone> ResolveZoneAsync(
        string apiKey,
        string apiSecret,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/dns-domain",
            apiKey,
            apiSecret,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Exoscale list DNS domains failed ({status}): {TrimBody(body)}");
        }

        var zones = ParseDomains(body);
        foreach (var candidate in CandidateZones(recordName))
        {
            if (zones.TryGetValue(candidate, out var id))
            {
                return new Zone(id, candidate);
            }
        }

        throw new InvalidOperationException($"Exoscale could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string apiKey,
        string apiSecret,
        string zoneId,
        string relativeName,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/dns-domain/{Uri.EscapeDataString(zoneId)}/record",
            apiKey,
            apiSecret,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return null;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Exoscale list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        foreach (var record in EnumerateRecords(doc.RootElement))
        {
            var type = ReadString(record, "type");
            var name = NormalizeHost(ReadString(record, "name") ?? string.Empty);
            var content = UnquoteTxt(ReadString(record, "content") ?? string.Empty);
            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesMatch(name, relativeName, recordName) &&
                string.Equals(content, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string apiKey,
        string apiSecret,
        string? content,
        CancellationToken cancellationToken)
    {
        var expires = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + SignatureTtlSeconds;
        var body = content ?? string.Empty;
        var uri = new Uri(url);
        var message = $"{method.Method} {uri.AbsolutePath}\n{body}\n\n\n{expires}";
        var signature = Convert.ToBase64String(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(apiSecret), Encoding.UTF8.GetBytes(message)));
        var authorization =
            $"EXO2-HMAC-SHA256 credential={apiKey},expires={expires},signature={signature}";

        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-ExoscaleDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        ThrowIfAuthFailed(status, responseBody);
        return (status, responseBody);
    }

    private static Dictionary<string, string> ParseDomains(string body)
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(body);
        foreach (var domain in EnumerateDomains(doc.RootElement))
        {
            var name = ReadString(domain, "unicode-name") ?? ReadString(domain, "name");
            var id = ReadId(domain, "id");
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(id))
            {
                names[NormalizeHost(name)] = id;
            }
        }

        return names;
    }

    private static IEnumerable<JsonElement> EnumerateDomains(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                yield return item;
            }

            yield break;
        }

        if (root.TryGetProperty("dns-domains", out var domains) && domains.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in domains.EnumerateArray())
            {
                yield return item;
            }
        }
    }

    private static IEnumerable<JsonElement> EnumerateRecords(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                yield return item;
            }

            yield break;
        }

        if (root.TryGetProperty("dns-domain-records", out var records) && records.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in records.EnumerateArray())
            {
                yield return item;
            }
        }
    }

    private static bool NamesMatch(string name, string relativeName, string recordName) =>
        string.Equals(name, relativeName, StringComparison.Ordinal) ||
        string.Equals(name, recordName, StringComparison.Ordinal);

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (status is 401 or 403)
        {
            throw new InvalidOperationException(
                $"Exoscale authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsAlreadyExists(string body) =>
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("\"conflict\"", StringComparison.OrdinalIgnoreCase);

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
            _ => null
        };
    }

    private static string? ReadId(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var id))
        {
            return null;
        }

        return id.ValueKind switch
        {
            JsonValueKind.Number => id.GetRawText(),
            JsonValueKind.String => id.GetString(),
            _ => null
        };
    }

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

    private sealed record Zone(string Id, string Name);
}
