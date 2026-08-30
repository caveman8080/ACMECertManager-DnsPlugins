using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace DigitalOceanDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DigitalOceanDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.digitalocean.com/v2";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "digitalocean",
        DisplayName = "DigitalOcean",
        Description = "DNS-01 via the DigitalOcean HTTP API using a personal access token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "DigitalOcean personal access token"
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

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            name = relative,
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
            throw new InvalidOperationException($"DigitalOcean add TXT failed ({status}): {TrimBody(body)}");
        }
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

        var url = $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records";
        while (!string.IsNullOrWhiteSpace(url))
        {
            var (status, body) = await SendAsync(HttpMethod.Get, url, token, content: null, cancellationToken).ConfigureAwait(false);
            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"DigitalOcean list records failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("domain_records", out var records) && records.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in records.EnumerateArray())
                {
                    var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                    var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                    var data = record.TryGetProperty("data", out var dataElement) ? dataElement.GetString() : null;
                    if (!string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(NormalizeHost(name ?? string.Empty), relative, StringComparison.Ordinal) ||
                        !string.Equals(data, request.TxtValue, StringComparison.Ordinal) ||
                        !record.TryGetProperty("id", out var idElement))
                    {
                        continue;
                    }

                    var id = idElement.ValueKind == JsonValueKind.Number
                        ? idElement.GetInt64().ToString()
                        : idElement.GetString();
                    if (string.IsNullOrWhiteSpace(id))
                    {
                        continue;
                    }

                    var (deleteStatus, deleteBody) = await SendAsync(
                        HttpMethod.Delete,
                        $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/{id}",
                        token,
                        content: null,
                        cancellationToken).ConfigureAwait(false);

                    if (deleteStatus is not (200 or 204 or 404) && deleteStatus is < 200 or >= 300)
                    {
                        throw new InvalidOperationException($"DigitalOcean delete TXT failed ({deleteStatus}): {TrimBody(deleteBody)}");
                    }
                }
            }

            url = TryGetNextPage(doc.RootElement);
        }
    }

    private static async Task<string> ResolveZoneAsync(string token, string recordName, CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, _) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(candidate)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"DigitalOcean could not find a domain zone for '{recordName}'.");
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
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DigitalOceanDnsPlugin");
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
        if (!root.TryGetProperty("links", out var links) ||
            !links.TryGetProperty("pages", out var pages) ||
            !pages.TryGetProperty("next", out var next))
        {
            return null;
        }

        var value = next.GetString();
        return string.IsNullOrWhiteSpace(value) ? null : value;
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
            return "@";
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
