using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace PowerDnsDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class PowerDnsDnsValidationPlugin : IDnsValidationPlugin
{
    private const int TxtTtl = 60;
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public PowerDnsDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public PowerDnsDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "powerdns",
        DisplayName = "PowerDNS",
        Description = "DNS-01 via the PowerDNS Authoritative HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiBaseUrl",
            Label = "API Base URL",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "https://pdns.example:8081"
        },
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "PowerDNS API key (X-API-Key)"
        },
        new DnsCredentialField
        {
            Name = "serverId",
            Label = "Server ID",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default localhost"
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
        var session = CreateSession(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zoneId = await ResolveZoneAsync(session, recordName, cancellationToken).ConfigureAwait(false);
        var existing = await GetTxtContentsAsync(session, zoneId, recordName, cancellationToken).ConfigureAwait(false);

        if (existing.Any(value => string.Equals(UnquoteTxt(value), request.TxtValue, StringComparison.Ordinal)))
        {
            return;
        }

        var records = existing
            .Select(value => new { content = QuoteTxt(value), disabled = false })
            .Append(new { content = QuoteTxt(request.TxtValue), disabled = false })
            .ToArray();

        var payload = JsonSerializer.Serialize(new
        {
            rrsets = new[]
            {
                new
                {
                    name = AbsoluteName(recordName),
                    type = "TXT",
                    ttl = TxtTtl,
                    changetype = "REPLACE",
                    records
                }
            }
        });

        var (status, body) = await SendAsync(
            session,
            HttpMethod.Patch,
            ZoneUrl(session, zoneId),
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300)
        {
            return;
        }

        throw new InvalidOperationException($"PowerDNS add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var session = CreateSession(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zoneId = await ResolveZoneAsync(session, recordName, cancellationToken).ConfigureAwait(false);
        var existing = await GetTxtContentsAsync(session, zoneId, recordName, cancellationToken).ConfigureAwait(false);
        if (existing.Count == 0)
        {
            return;
        }

        var remaining = existing
            .Where(value => !string.Equals(UnquoteTxt(value), request.TxtValue, StringComparison.Ordinal))
            .ToList();
        if (remaining.Count == existing.Count)
        {
            return;
        }

        object payload;
        if (remaining.Count == 0)
        {
            payload = new
            {
                rrsets = new[]
                {
                    new
                    {
                        name = AbsoluteName(recordName),
                        type = "TXT",
                        changetype = "DELETE"
                    }
                }
            };
        }
        else
        {
            payload = new
            {
                rrsets = new[]
                {
                    new
                    {
                        name = AbsoluteName(recordName),
                        type = "TXT",
                        ttl = TxtTtl,
                        changetype = "REPLACE",
                        records = remaining
                            .Select(value => new { content = QuoteTxt(value), disabled = false })
                            .ToArray()
                    }
                }
            };
        }

        var (status, body) = await SendAsync(
            session,
            HttpMethod.Patch,
            ZoneUrl(session, zoneId),
            JsonSerializer.Serialize(payload),
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || status is 404)
        {
            return;
        }

        throw new InvalidOperationException($"PowerDNS delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        Session session,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            session,
            HttpMethod.Get,
            ZonesUrl(session),
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"PowerDNS list zones failed ({status}): {TrimBody(body)}");
        }

        var zones = ParseZones(body);
        foreach (var candidate in CandidateZones(recordName))
        {
            if (zones.TryGetValue(candidate, out var zoneId))
            {
                return zoneId;
            }
        }

        throw new InvalidOperationException($"PowerDNS could not find a DNS zone for '{recordName}'.");
    }

    private async Task<List<string>> GetTxtContentsAsync(
        Session session,
        string zoneId,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            session,
            HttpMethod.Get,
            ZoneUrl(session, zoneId),
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return [];
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"PowerDNS get zone failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("rrsets", out var rrsets) || rrsets.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var values = new List<string>();
        foreach (var rrset in rrsets.EnumerateArray())
        {
            var type = rrset.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            var name = rrset.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            if (!string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(NormalizeHost(name ?? string.Empty), recordName, StringComparison.Ordinal))
            {
                continue;
            }

            if (!rrset.TryGetProperty("records", out var records) || records.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var record in records.EnumerateArray())
            {
                var content = record.TryGetProperty("content", out var contentElement)
                    ? contentElement.GetString()
                    : null;
                if (!string.IsNullOrWhiteSpace(content))
                {
                    values.Add(content);
                }
            }
        }

        return values;
    }

    private async Task<(int Status, string Body)> SendAsync(
        Session session,
        HttpMethod method,
        string url,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("X-API-Key", session.ApiKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-PowerDnsDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        if (status is 401 or 403)
        {
            throw new InvalidOperationException(
                $"PowerDNS authentication/authorization failed ({status}): {TrimBody(body)}");
        }

        return (status, body);
    }

    private static Session CreateSession(IReadOnlyDictionary<string, string> credentials) =>
        new(
            NormalizeBaseUrl(GetRequired(credentials, "apiBaseUrl")),
            GetRequired(credentials, "apiKey"),
            GetOptional(credentials, "serverId", "localhost"));

    private static Dictionary<string, string> ParseZones(string body)
    {
        var zones = new Dictionary<string, string>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return zones;
        }

        foreach (var zone in doc.RootElement.EnumerateArray())
        {
            var name = zone.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var id = zone.TryGetProperty("id", out var idElement) ? idElement.GetString() : null;
            if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var zoneId = !string.IsNullOrWhiteSpace(id) ? id : AbsoluteName(name!);
            zones[NormalizeHost(name ?? id!)] = zoneId;
        }

        return zones;
    }

    private static string ZonesUrl(Session session) =>
        $"{session.BaseUrl}/api/v1/servers/{Uri.EscapeDataString(session.ServerId)}/zones";

    private static string ZoneUrl(Session session, string zoneId) =>
        $"{ZonesUrl(session)}/{Uri.EscapeDataString(zoneId)}";

    private static string NormalizeBaseUrl(string url)
    {
        var trimmed = url.Trim().TrimEnd('/');
        const string apiSuffix = "/api/v1";
        if (trimmed.EndsWith(apiSuffix, StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[..^apiSuffix.Length].TrimEnd('/');
        }

        return trimmed;
    }

    private static string QuoteTxt(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
        {
            return trimmed;
        }

        return $"\"{trimmed}\"";
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

    private static string GetOptional(IReadOnlyDictionary<string, string> credentials, string key, string fallback)
    {
        if (!credentials.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return value.Trim();
    }

    private static string AbsoluteName(string host) => NormalizeHost(host) + ".";

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }

    private sealed record Session(string BaseUrl, string ApiKey, string ServerId);
}
