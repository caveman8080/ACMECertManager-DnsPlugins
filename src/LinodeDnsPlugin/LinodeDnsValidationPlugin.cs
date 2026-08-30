using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace LinodeDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class LinodeDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.linode.com/v4/domains";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "linode",
        DisplayName = "Linode",
        Description = "DNS-01 via the Linode HTTP API v4 using a personal access token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Linode personal access token (LINODE_V4_API_KEY)"
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
        var relative = GetRelativeName(recordName, zone.Name);

        var existingId = await FindRecordIdAsync(token, zone.Id, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            name = relative,
            target = request.TxtValue,
            ttl_sec = 300
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/{Uri.EscapeDataString(zone.Id)}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Linode add TXT failed ({status}): {TrimBody(body)}");
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
        var relative = GetRelativeName(recordName, zone.Name);
        var recordId = await FindRecordIdAsync(token, zone.Id, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/{Uri.EscapeDataString(zone.Id)}/records/{Uri.EscapeDataString(recordId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Linode delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string token,
        string recordName,
        CancellationToken cancellationToken)
    {
        var page = 1;
        while (true)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}?page={page}&page_size=100",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Linode list domains failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            var names = new Dictionary<string, string>(StringComparer.Ordinal);
            if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            {
                foreach (var domain in data.EnumerateArray())
                {
                    var name = domain.TryGetProperty("domain", out var nameElement) ? nameElement.GetString() : null;
                    var id = ReadId(domain, "id");
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

            var pages = doc.RootElement.TryGetProperty("pages", out var pagesElement) && pagesElement.TryGetInt32(out var total)
                ? total
                : page;
            if (page >= pages)
            {
                break;
            }

            page++;
        }

        throw new InvalidOperationException($"Linode could not find a domain zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string token,
        string zoneId,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var page = 1;
        while (true)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/{Uri.EscapeDataString(zoneId)}/records?page={page}&page_size=100",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Linode list records failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in data.EnumerateArray())
                {
                    var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                    var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                    var target = record.TryGetProperty("target", out var targetElement) ? targetElement.GetString() : null;
                    var id = ReadId(record, "id");
                    if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(NormalizeHost(name ?? string.Empty), relativeName, StringComparison.Ordinal) &&
                        string.Equals(UnquoteTxt(target ?? string.Empty), txtValue, StringComparison.Ordinal) &&
                        !string.IsNullOrWhiteSpace(id))
                    {
                        return id;
                    }
                }
            }

            var pages = doc.RootElement.TryGetProperty("pages", out var pagesElement) && pagesElement.TryGetInt32(out var total)
                ? total
                : page;
            if (page >= pages)
            {
                return null;
            }

            page++;
        }
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
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-LinodeDnsPlugin");
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
