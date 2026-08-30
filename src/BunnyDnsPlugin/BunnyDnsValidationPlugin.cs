using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace BunnyDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class BunnyDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.bunny.net";
    private const int TxtType = 3;
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "bunny",
        DisplayName = "Bunny.net DNS",
        Description = "DNS-01 via the Bunny.net DNS HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Bunny.net account API key"
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
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone.Name);

        var existingId = await FindRecordIdAsync(apiKey, zone.Id, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            Type = TxtType,
            Name = relative,
            Value = request.TxtValue,
            Ttl = 120
        });

        var (status, body) = await SendAsync(
            HttpMethod.Put,
            $"{ApiBase}/dnszone/{Uri.EscapeDataString(zone.Id)}/records",
            apiKey,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Bunny.net add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone.Name);
        var recordId = await FindRecordIdAsync(apiKey, zone.Id, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/dnszone/{Uri.EscapeDataString(zone.Id)}/records/{Uri.EscapeDataString(recordId)}",
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Bunny.net delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        var page = 1;
        while (true)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/dnszone?page={page}",
                apiKey,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Bunny.net list zones failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            var names = new Dictionary<string, string>(StringComparer.Ordinal);
            if (doc.RootElement.TryGetProperty("Items", out var items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (var zone in items.EnumerateArray())
                {
                    var name = zone.TryGetProperty("Domain", out var nameElement) ? nameElement.GetString() : null;
                    var id = ReadId(zone, "Id");
                    if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(id))
                    {
                        names[NormalizeHost(name)] = id;
                    }
                }
            }

            foreach (var candidate in CandidateZones(recordName))
            {
                if (names.TryGetValue(candidate, out var id))
                {
                    return (id, candidate);
                }
            }

            var hasMore = doc.RootElement.TryGetProperty("HasMoreItems", out var more) && more.ValueKind == JsonValueKind.True;
            if (!hasMore)
            {
                break;
            }

            page++;
        }

        throw new InvalidOperationException($"Bunny.net could not find a DNS zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string apiKey,
        string zoneId,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/dnszone/{Uri.EscapeDataString(zoneId)}",
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Bunny.net get zone failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("Records", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = ReadInt(record, "Type");
            var name = record.TryGetProperty("Name", out var nameElement) ? nameElement.GetString() : null;
            var value = record.TryGetProperty("Value", out var valueElement) ? valueElement.GetString() : null;
            var id = ReadId(record, "Id");
            if (type == TxtType &&
                string.Equals(NormalizeHost(name ?? string.Empty), relativeName, StringComparison.Ordinal) &&
                string.Equals(UnquoteTxt(value ?? string.Empty), txtValue, StringComparison.Ordinal) &&
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
        request.Headers.TryAddWithoutValidation("AccessKey", apiKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-BunnyDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
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

    private static int? ReadInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), out var parsed))
        {
            return parsed;
        }

        return null;
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
}
