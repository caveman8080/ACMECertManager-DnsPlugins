using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace InfomaniakDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class InfomaniakDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.infomaniak.com";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public InfomaniakDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public InfomaniakDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "infomaniak",
        DisplayName = "Infomaniak",
        Description = "DNS-01 via the Infomaniak HTTP API using a bearer API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Infomaniak API token (INFOMANIAK_API_TOKEN)"
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
        var token = GetRequired(credentials, "apiToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existingId = await FindRecordIdAsync(token, zone, relative, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            source = relative,
            target = request.TxtValue,
            ttl = 300
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/2/zones/{Uri.EscapeDataString(zone)}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 ||
            body.Contains("already", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException($"Infomaniak add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "apiToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(token, zone, relative, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/2/zones/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(recordId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || status is 404)
        {
            return;
        }

        throw new InvalidOperationException($"Infomaniak delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string token,
        string recordName,
        CancellationToken cancellationToken)
    {
        var fromFull = await TryGetZoneFqdnAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(fromFull))
        {
            return fromFull;
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            var fqdn = await TryGetZoneFqdnAsync(token, candidate, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(fqdn))
            {
                return fqdn;
            }

            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/2/zones/{Uri.EscapeDataString(candidate)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(status, body);

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"Infomaniak could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> TryGetZoneFqdnAsync(
        string token,
        string domain,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/2/domains/{Uri.EscapeDataString(domain)}/zones",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body);

        if (status is < 200 or >= 300)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var fqdn = ReadFirstFqdn(doc.RootElement);
            return string.IsNullOrWhiteSpace(fqdn) ? null : NormalizeHost(fqdn);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task<string?> FindRecordIdAsync(
        string token,
        string zone,
        string relativeName,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/2/zones/{Uri.EscapeDataString(zone)}/records",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Infomaniak list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        foreach (var record in EnumerateRecords(doc.RootElement))
        {
            var type = ReadString(record, "type");
            var source = ReadString(record, "source") ?? string.Empty;
            var sourceIdn = ReadString(record, "source_idn") ?? string.Empty;
            var target = UnquoteTxt(ReadString(record, "target") ?? string.Empty);
            var targetIdn = UnquoteTxt(ReadString(record, "target_idn") ?? string.Empty);
            var id = ReadId(record, "id");
            var normalizedSource = NormalizeHost(source);
            var normalizedSourceIdn = NormalizeHost(sourceIdn);

            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesMatch(normalizedSource, normalizedSourceIdn, relativeName, recordName, zone) &&
                (string.Equals(target, txtValue, StringComparison.Ordinal) ||
                 string.Equals(targetIdn, txtValue, StringComparison.Ordinal)) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private static IEnumerable<JsonElement> EnumerateRecords(JsonElement root)
    {
        if (root.TryGetProperty("data", out var data))
        {
            if (data.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in data.EnumerateArray())
                {
                    yield return item;
                }

                yield break;
            }

            if (data.ValueKind == JsonValueKind.Object &&
                data.TryGetProperty("records", out var nested) &&
                nested.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in nested.EnumerateArray())
                {
                    yield return item;
                }
            }
        }
    }

    private static bool NamesMatch(string source, string sourceIdn, string relative, string recordName, string zone)
    {
        foreach (var name in new[] { source, sourceIdn })
        {
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }

            if (string.Equals(name, relative, StringComparison.Ordinal) ||
                string.Equals(name, recordName, StringComparison.Ordinal) ||
                string.Equals(name, $"{relative}.{zone}", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return relative.Length == 0 &&
               (source.Length == 0 || string.Equals(source, zone, StringComparison.Ordinal));
    }

    private static string? ReadFirstFqdn(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty("fqdn", out var fqdnElement))
        {
            var value = fqdnElement.GetString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty("data", out var data))
        {
            var nested = ReadFirstFqdn(data);
            if (!string.IsNullOrWhiteSpace(nested))
            {
                return nested;
            }
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var nested = ReadFirstFqdn(item);
                if (!string.IsNullOrWhiteSpace(nested))
                {
                    return nested;
                }
            }
        }

        return null;
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string token,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-InfomaniakDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (status is 401 or 403)
        {
            throw new InvalidOperationException(
                $"Infomaniak authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetString() : null;

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
