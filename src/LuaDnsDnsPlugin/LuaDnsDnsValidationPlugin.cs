using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace LuaDnsDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class LuaDnsDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.luadns.com/v1";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "luadns",
        DisplayName = "LuaDNS",
        Description = "DNS-01 via the LuaDNS HTTP API using account email and API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "email",
            Label = "Email",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "LuaDNS account email"
        },
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "LuaDNS API key"
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
        var email = GetRequired(credentials, "email");
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(email, apiKey, recordName, cancellationToken).ConfigureAwait(false);

        var existingId = await FindRecordIdAsync(email, apiKey, zone.Id, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            name = recordName + ".",
            content = request.TxtValue,
            ttl = 120
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone.Id)}/records",
            email,
            apiKey,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"LuaDNS add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var email = GetRequired(credentials, "email");
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(email, apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var recordId = await FindRecordIdAsync(email, apiKey, zone.Id, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone.Id)}/records/{Uri.EscapeDataString(recordId)}",
            email,
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"LuaDNS delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string email,
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(HttpMethod.Get, $"{ApiBase}/zones", email, apiKey, content: null, cancellationToken).ConfigureAwait(false);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"LuaDNS list zones failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var zone in doc.RootElement.EnumerateArray())
            {
                var name = zone.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                var id = ReadId(zone, "id");
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

        throw new InvalidOperationException($"LuaDNS could not find a zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string email,
        string apiKey,
        string zoneId,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zoneId)}/records",
            email,
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"LuaDNS list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in doc.RootElement.EnumerateArray())
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
        string email,
        string apiKey,
        string? content,
        CancellationToken cancellationToken)
    {
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{email}:{apiKey}"));
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {basic}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-LuaDnsDnsPlugin");
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
