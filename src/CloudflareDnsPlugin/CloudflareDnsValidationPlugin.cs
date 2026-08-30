using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace CloudflareDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class CloudflareDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.cloudflare.com/client/v4";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "cloudflare",
        DisplayName = "Cloudflare",
        Description = "DNS-01 via the Cloudflare HTTP API (API token). Zone ID is optional when the token can list zones."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Cloudflare API token with Zone.DNS Edit"
        },
        new DnsCredentialField
        {
            Name = "zoneId",
            Label = "Zone ID",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional; leave blank to detect from the record name"
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
        var zoneId = GetOptional(credentials, "zoneId");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, zoneId, cancellationToken).ConfigureAwait(false);

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            name = recordName,
            content = request.TxtValue,
            ttl = 120
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone.Id)}/dns_records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (IsSuccess(body) && body.Contains(request.TxtValue, StringComparison.Ordinal))
        {
            return;
        }

        if (IsIdenticalRecord(body))
        {
            return;
        }

        throw new InvalidOperationException($"Cloudflare add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "apiToken");
        var zoneId = GetOptional(credentials, "zoneId");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, zoneId, cancellationToken).ConfigureAwait(false);

        var query =
            $"type=TXT&name={Uri.EscapeDataString(recordName)}&content={Uri.EscapeDataString(request.TxtValue)}";
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone.Id)}/dns_records?{query}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (!IsSuccess(body))
        {
            throw new InvalidOperationException($"Cloudflare list TXT failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var record in result.EnumerateArray())
        {
            if (!record.TryGetProperty("id", out var idElement))
            {
                continue;
            }

            var recordId = idElement.GetString();
            if (string.IsNullOrWhiteSpace(recordId))
            {
                continue;
            }

            var (deleteStatus, deleteBody) = await SendAsync(
                HttpMethod.Delete,
                $"{ApiBase}/zones/{Uri.EscapeDataString(zone.Id)}/dns_records/{Uri.EscapeDataString(recordId)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (!IsSuccess(deleteBody) && deleteStatus is not (404 or 200 or 204))
            {
                throw new InvalidOperationException($"Cloudflare delete TXT failed ({deleteStatus}): {TrimBody(deleteBody)}");
            }
        }
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string token,
        string recordName,
        string? zoneId,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(zoneId))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/zones/{Uri.EscapeDataString(zoneId)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (!IsSuccess(body))
            {
                throw new InvalidOperationException($"Cloudflare zone '{zoneId}' lookup failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            var name = doc.RootElement.GetProperty("result").GetProperty("name").GetString();
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new InvalidOperationException($"Cloudflare zone '{zoneId}' did not return a name.");
            }

            return (zoneId, NormalizeHost(name));
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/zones?name={Uri.EscapeDataString(candidate)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (!IsSuccess(body))
            {
                continue;
            }

            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var zone in result.EnumerateArray())
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

        throw new InvalidOperationException($"Cloudflare could not find a zone for '{recordName}'. Set Zone ID or grant Zone.Zone Read.");
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
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-CloudflareDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static bool IsSuccess(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("success", out var success) && success.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsIdenticalRecord(string body)
    {
        if (body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("\"code\":81058", StringComparison.Ordinal))
        {
            return true;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("errors", out var errors) || errors.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var error in errors.EnumerateArray())
            {
                if (error.TryGetProperty("code", out var code) && code.TryGetInt32(out var value) && value == 81058)
                {
                    return true;
                }
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
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

    private static string? GetOptional(IReadOnlyDictionary<string, string> credentials, string key)
    {
        if (!credentials.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            return null;
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
