using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace GandiDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class GandiDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.gandi.net/v5/livedns";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "gandi",
        DisplayName = "Gandi LiveDNS",
        Description = "DNS-01 via the Gandi LiveDNS HTTP API using a personal access token (or deprecated API key)."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "Personal Access Token",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Gandi PAT (preferred)"
        },
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key (deprecated)",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Deprecated Gandi API key; used if PAT is blank"
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
        var auth = GetAuthorization(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(auth, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existing = await ListTxtAsync(auth, zone, relative, cancellationToken).ConfigureAwait(false);
        if (existing.Contains(request.TxtValue, StringComparer.Ordinal))
        {
            return;
        }

        var merged = existing.Concat([request.TxtValue]).ToArray();
        await PutTxtAsync(auth, zone, relative, merged, cancellationToken).ConfigureAwait(false);
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var auth = GetAuthorization(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(auth, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existing = await ListTxtAsync(auth, zone, relative, cancellationToken).ConfigureAwait(false);
        if (!existing.Contains(request.TxtValue, StringComparer.Ordinal))
        {
            return;
        }

        var remaining = existing.Where(value => value != request.TxtValue).ToArray();
        if (remaining.Length == 0)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Delete,
                $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(relative)}/TXT",
                auth,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Gandi delete TXT failed ({status}): {TrimBody(body)}");
            }

            return;
        }

        await PutTxtAsync(auth, zone, relative, remaining, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ResolveZoneAsync(
        string authorization,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(candidate)}",
                authorization,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status == 401)
            {
                throw new InvalidOperationException($"Gandi authentication failed ({status}): {TrimBody(body)}");
            }

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"Gandi could not find a LiveDNS zone for '{recordName}'.");
    }

    private static async Task<List<string>> ListTxtAsync(
        string authorization,
        string zone,
        string relative,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(relative)}/TXT",
            authorization,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return [];
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Gandi list TXT failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        var values = new List<string>();
        if (doc.RootElement.TryGetProperty("rrset_values", out var rrset) && rrset.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in rrset.EnumerateArray())
            {
                var raw = item.GetString();
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    values.Add(UnquoteTxt(raw));
                }
            }
        }

        return values;
    }

    private static async Task PutTxtAsync(
        string authorization,
        string zone,
        string relative,
        IReadOnlyList<string> values,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new
        {
            rrset_ttl = 300,
            rrset_values = values
        });

        var (status, body) = await SendAsync(
            HttpMethod.Put,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(relative)}/TXT",
            authorization,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Gandi update TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string authorization,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-GandiDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static string GetAuthorization(IReadOnlyDictionary<string, string> credentials)
    {
        var token = GetOptional(credentials, "apiToken");
        if (!string.IsNullOrWhiteSpace(token))
        {
            return $"Bearer {token}";
        }

        var apiKey = GetOptional(credentials, "apiKey");
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            return $"Apikey {apiKey}";
        }

        throw new InvalidOperationException("Missing required credential 'apiToken' or 'apiKey'.");
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
            return "@";
        }

        if (fqdn.EndsWith("." + zone, StringComparison.Ordinal))
        {
            return fqdn[..^(zone.Length + 1)];
        }

        throw new InvalidOperationException($"Record '{fqdn}' is not in zone '{zone}'.");
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
