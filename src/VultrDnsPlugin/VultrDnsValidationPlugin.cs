using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace VultrDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class VultrDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.vultr.com/v2";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "vultr",
        DisplayName = "Vultr",
        Description = "DNS-01 via the Vultr HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Vultr API key"
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
        var token = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existingId = await FindRecordIdAsync(token, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            name = relative,
            type = "TXT",
            data = request.TxtValue,
            ttl = 120
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Vultr add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(token, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(recordId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Vultr delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<string> ResolveZoneAsync(string token, string recordName, CancellationToken cancellationToken)
    {
        var url = $"{ApiBase}/domains";
        var zones = new HashSet<string>(StringComparer.Ordinal);
        while (!string.IsNullOrWhiteSpace(url))
        {
            var (status, body) = await SendAsync(HttpMethod.Get, url, token, content: null, cancellationToken).ConfigureAwait(false);
            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Vultr list domains failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("domains", out var domains) && domains.ValueKind == JsonValueKind.Array)
            {
                foreach (var domain in domains.EnumerateArray())
                {
                    var name = domain.TryGetProperty("domain", out var nameElement) ? nameElement.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        zones.Add(NormalizeHost(name));
                    }
                }
            }

            foreach (var candidate in CandidateZones(recordName))
            {
                if (zones.Contains(candidate))
                {
                    return candidate;
                }
            }

            url = TryGetNextPage(doc.RootElement);
        }

        throw new InvalidOperationException($"Vultr could not find a domain zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string token,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var url = $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records";
        while (!string.IsNullOrWhiteSpace(url))
        {
            var (status, body) = await SendAsync(HttpMethod.Get, url, token, content: null, cancellationToken).ConfigureAwait(false);
            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Vultr list records failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("records", out var records) && records.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in records.EnumerateArray())
                {
                    var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                    var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                    var data = record.TryGetProperty("data", out var dataElement) ? dataElement.GetString() : null;
                    var id = ReadId(record, "id");
                    if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(NormalizeHost(name ?? string.Empty), relativeName, StringComparison.Ordinal) &&
                        string.Equals(UnquoteTxt(data ?? string.Empty), txtValue, StringComparison.Ordinal) &&
                        !string.IsNullOrWhiteSpace(id))
                    {
                        return id;
                    }
                }
            }

            url = TryGetNextPage(doc.RootElement);
        }

        return null;
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string token,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-VultrDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static string? TryGetNextPage(JsonElement root)
    {
        if (!root.TryGetProperty("meta", out var meta) ||
            !meta.TryGetProperty("links", out var links) ||
            !links.TryGetProperty("next", out var next))
        {
            return null;
        }

        var value = next.GetString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
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
}
