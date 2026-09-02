using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace IonosDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class IonosDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.hosting.ionos.com/dns/v1/zones";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "ionos",
        DisplayName = "IONOS",
        Description = "DNS-01 via the IONOS DNS HTTP API using an API prefix and secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiPrefix",
            Label = "API Prefix",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "IONOS API prefix (IONOS_PREFIX)"
        },
        new DnsCredentialField
        {
            Name = "apiSecret",
            Label = "API Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "IONOS API secret (IONOS_SECRET)"
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
        var apiKey = GetApiKey(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);

        var existingId = await FindRecordIdAsync(apiKey, zone.Id, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new[]
        {
            new
            {
                name = recordName,
                type = "TXT",
                content = request.TxtValue,
                ttl = 60
            }
        });
        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/{Uri.EscapeDataString(zone.Id)}/records",
            apiKey,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is not 201 && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"IONOS add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetApiKey(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var recordId = await FindRecordIdAsync(apiKey, zone.Id, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/{Uri.EscapeDataString(zone.Id)}/records/{Uri.EscapeDataString(recordId)}",
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"IONOS delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            ApiBase,
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"IONOS list zones failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException($"IONOS list zones failed: {TrimBody(body)}");
        }

        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var zone in doc.RootElement.EnumerateArray())
        {
            var name = zone.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var id = ReadId(zone, "id");
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(id))
            {
                names[NormalizeHost(name)] = id;
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            if (names.TryGetValue(candidate, out var id))
            {
                return (id, candidate);
            }
        }

        throw new InvalidOperationException($"IONOS could not find a DNS zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string apiKey,
        string zoneId,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/{Uri.EscapeDataString(zoneId)}?recordName={Uri.EscapeDataString(recordName)}&recordType=TXT",
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"IONOS list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("records", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var content = record.TryGetProperty("content", out var contentElement) ? contentElement.GetString() : null;
            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(NormalizeHost(name ?? string.Empty), recordName, StringComparison.Ordinal) &&
                string.Equals(UnquoteTxt(content ?? string.Empty), txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string apiKey,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("X-API-Key", apiKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-IonosDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static string GetApiKey(IReadOnlyDictionary<string, string> credentials)
    {
        var prefix = GetRequired(credentials, "apiPrefix");
        var secret = GetRequired(credentials, "apiSecret");
        return $"{prefix}.{secret}";
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
