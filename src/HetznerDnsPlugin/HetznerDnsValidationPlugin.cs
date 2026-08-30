using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace HetznerDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class HetznerDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://dns.hetzner.com/api/v1";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "hetzner",
        DisplayName = "Hetzner DNS",
        Description = "DNS-01 via the Hetzner DNS HTTP API (dns.hetzner.com) using an API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Hetzner DNS API token"
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
        var relative = GetRelativeName(recordName, zone.Name);

        var existingId = await FindRecordIdAsync(token, zone.Id, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            zone_id = zone.Id,
            type = "TXT",
            name = relative,
            value = request.TxtValue,
            ttl = 120
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300 || !body.Contains(request.TxtValue, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Hetzner add TXT failed ({status}): {TrimBody(body)}");
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
        var relative = GetRelativeName(recordName, zone.Name);
        var recordId = await FindRecordIdAsync(token, zone.Id, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/records/{Uri.EscapeDataString(recordId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Hetzner delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string token,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/zones?name={Uri.EscapeDataString(candidate)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300)
            {
                continue;
            }

            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("zones", out var zones) || zones.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var zone in zones.EnumerateArray())
            {
                var name = zone.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                var id = zone.TryGetProperty("id", out var idElement) ? idElement.GetString() : null;
                if (!string.IsNullOrWhiteSpace(id) &&
                    string.Equals(NormalizeHost(name ?? string.Empty), candidate, StringComparison.Ordinal))
                {
                    return (id, candidate);
                }
            }
        }

        throw new InvalidOperationException($"Hetzner could not find a zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string token,
        string zoneId,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/records?zone_id={Uri.EscapeDataString(zoneId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Hetzner list records failed ({status}): {TrimBody(body)}");
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
            var value = record.TryGetProperty("value", out var valueElement) ? valueElement.GetString() : null;
            var id = record.TryGetProperty("id", out var idElement) ? idElement.GetString() : null;
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(NormalizeHost(name ?? string.Empty), relativeName, StringComparison.Ordinal) &&
                string.Equals(value, txtValue, StringComparison.Ordinal) &&
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
        string token,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Auth-API-Token", token);
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-HetznerDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
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
