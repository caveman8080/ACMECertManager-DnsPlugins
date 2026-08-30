using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace GoDaddyDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class GoDaddyDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.godaddy.com/v1";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "godaddy",
        DisplayName = "GoDaddy",
        Description = "DNS-01 via the GoDaddy HTTP API using an API key and secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "GoDaddy API key"
        },
        new DnsCredentialField
        {
            Name = "apiSecret",
            Label = "API Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "GoDaddy API secret"
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
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existing = await ListTxtAsync(apiKey, apiSecret, zone, relative, cancellationToken).ConfigureAwait(false);
        if (existing.Contains(request.TxtValue, StringComparer.Ordinal))
        {
            return;
        }

        var merged = existing.Concat([request.TxtValue]).Select(value => new { data = value }).ToArray();
        var payload = JsonSerializer.Serialize(merged);
        var (status, body) = await SendAsync(
            HttpMethod.Put,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/TXT/{Uri.EscapeDataString(relative)}",
            apiKey,
            apiSecret,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"GoDaddy add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existing = await ListTxtAsync(apiKey, apiSecret, zone, relative, cancellationToken).ConfigureAwait(false);
        if (!existing.Contains(request.TxtValue, StringComparer.Ordinal))
        {
            return;
        }

        var remaining = existing.Where(value => value != request.TxtValue).ToArray();
        if (remaining.Length == 0)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Delete,
                $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/TXT/{Uri.EscapeDataString(relative)}",
                apiKey,
                apiSecret,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"GoDaddy delete TXT failed ({status}): {TrimBody(body)}");
            }

            return;
        }

        var payload = JsonSerializer.Serialize(remaining.Select(value => new { data = value }).ToArray());
        var (putStatus, putBody) = await SendAsync(
            HttpMethod.Put,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/TXT/{Uri.EscapeDataString(relative)}",
            apiKey,
            apiSecret,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (putStatus is < 200 or >= 300)
        {
            throw new InvalidOperationException($"GoDaddy update TXT failed ({putStatus}): {TrimBody(putBody)}");
        }
    }

    private static async Task<string> ResolveZoneAsync(
        string apiKey,
        string apiSecret,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var relative = GetRelativeName(recordName, candidate);
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(candidate)}/records/TXT/{Uri.EscapeDataString(relative)}",
                apiKey,
                apiSecret,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is >= 200 and < 300 && LooksLikeJsonArray(body))
            {
                return candidate;
            }

            var (domainStatus, domainBody) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(candidate)}",
                apiKey,
                apiSecret,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (domainStatus is >= 200 and < 300 && domainBody.Contains("\"domainId\"", StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"GoDaddy could not find a domain zone for '{recordName}'.");
    }

    private static async Task<List<string>> ListTxtAsync(
        string apiKey,
        string apiSecret,
        string zone,
        string relative,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/TXT/{Uri.EscapeDataString(relative)}",
            apiKey,
            apiSecret,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404 || body.Contains("UNKNOWN_DOMAIN", StringComparison.Ordinal))
        {
            return [];
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"GoDaddy list TXT failed ({status}): {TrimBody(body)}");
        }

        if (!LooksLikeJsonArray(body))
        {
            return [];
        }

        using var doc = JsonDocument.Parse(body);
        var values = new List<string>();
        foreach (var record in doc.RootElement.EnumerateArray())
        {
            var data = record.TryGetProperty("data", out var dataElement) ? dataElement.GetString() : null;
            if (!string.IsNullOrWhiteSpace(data))
            {
                values.Add(data);
            }
        }

        return values;
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string apiKey,
        string apiSecret,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"sso-key {apiKey}:{apiSecret}");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-GoDaddyDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (body.Contains("UNABLE_TO_AUTHENTICATE", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("GoDaddy API key or secret is not correct.");
        }

        return ((int)response.StatusCode, body);
    }

    private static bool LooksLikeJsonArray(string body)
    {
        var trimmed = body.TrimStart();
        return trimmed.StartsWith("[", StringComparison.Ordinal);
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
