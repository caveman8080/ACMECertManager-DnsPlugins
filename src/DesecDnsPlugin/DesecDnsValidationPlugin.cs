using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace DesecDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DesecDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://desec.io/api/v1/domains";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "desec",
        DisplayName = "deSEC",
        Description = "DNS-01 via the deSEC HTTP API using an API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "deSEC token (DEDYN_TOKEN)"
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
        var subname = GetSubname(recordName, zone);

        var values = await GetTxtValuesAsync(token, zone, subname, cancellationToken).ConfigureAwait(false);
        if (!values.Contains(request.TxtValue, StringComparer.Ordinal))
        {
            values.Add(request.TxtValue);
        }

        await PutTxtAsync(token, zone, subname, values, cancellationToken).ConfigureAwait(false);
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "apiToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var subname = GetSubname(recordName, zone);

        var values = await GetTxtValuesAsync(token, zone, subname, cancellationToken).ConfigureAwait(false);
        var remaining = values.Where(value => value != request.TxtValue).ToList();
        await PutTxtAsync(token, zone, subname, remaining, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ResolveZoneAsync(string token, string recordName, CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(HttpMethod.Get, $"{ApiBase}/", token, content: null, cancellationToken).ConfigureAwait(false);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"deSEC list domains failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        var names = new HashSet<string>(StringComparer.Ordinal);
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var domain in doc.RootElement.EnumerateArray())
            {
                var name = domain.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    names.Add(NormalizeHost(name));
                }
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            if (names.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"deSEC could not find a domain zone for '{recordName}'.");
    }

    private static async Task<List<string>> GetTxtValuesAsync(
        string token,
        string zone,
        string subname,
        CancellationToken cancellationToken)
    {
        var encodedSub = Uri.EscapeDataString(subname);
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/{Uri.EscapeDataString(zone)}/rrsets/{encodedSub}/TXT/",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status == 404)
        {
            return [];
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"deSEC get TXT failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        var values = new List<string>();
        if (doc.RootElement.TryGetProperty("records", out var records) && records.ValueKind == JsonValueKind.Array)
        {
            foreach (var record in records.EnumerateArray())
            {
                var raw = record.GetString();
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    values.Add(UnquoteTxt(raw));
                }
            }
        }

        return values;
    }

    private static async Task PutTxtAsync(
        string token,
        string zone,
        string subname,
        IReadOnlyList<string> values,
        CancellationToken cancellationToken)
    {
        var quoted = values.Select(value => $"\"{value}\"").ToArray();
        var payload = JsonSerializer.Serialize(new[]
        {
            new
            {
                subname,
                type = "TXT",
                records = quoted,
                ttl = 3600
            }
        });

        var (status, body) = await SendAsync(
            HttpMethod.Put,
            $"{ApiBase}/{Uri.EscapeDataString(zone)}/rrsets/",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        await Task.Delay(1000, cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"deSEC update TXT failed ({status}): {TrimBody(body)}");
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
        request.Headers.TryAddWithoutValidation("Authorization", $"Token {token}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DesecDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
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

    private static string GetSubname(string fqdn, string zone)
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
