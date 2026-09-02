using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace ScalewayDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class ScalewayDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.scaleway.com/domain/v2beta1";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "scaleway",
        DisplayName = "Scaleway",
        Description = "DNS-01 via the Scaleway Domains and DNS HTTP API using an API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Scaleway API token (SCALEWAY_API_TOKEN)"
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
        await EnsureTokenAsync(token, cancellationToken).ConfigureAwait(false);

        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        if (await HasTxtAsync(token, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            return_all_records = false,
            changes = new[]
            {
                new
                {
                    add = new
                    {
                        records = new[]
                        {
                            new
                            {
                                name = relative,
                                data = request.TxtValue,
                                type = "TXT",
                                ttl = 60
                            }
                        }
                    }
                }
            }
        });

        var (status, body) = await SendAsync(
            HttpMethod.Patch,
            $"{ApiBase}/dns-zones/{Uri.EscapeDataString(zone)}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300 || !body.Contains("records", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Scaleway add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "apiToken");
        await EnsureTokenAsync(token, cancellationToken).ConfigureAwait(false);

        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        if (!await HasTxtAsync(token, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            return_all_records = false,
            changes = new[]
            {
                new
                {
                    delete = new
                    {
                        id_fields = new
                        {
                            name = relative,
                            data = request.TxtValue,
                            type = "TXT"
                        }
                    }
                }
            }
        });

        var (status, body) = await SendAsync(
            HttpMethod.Patch,
            $"{ApiBase}/dns-zones/{Uri.EscapeDataString(zone)}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && (status is < 200 or >= 300 || !body.Contains("records", StringComparison.Ordinal)))
        {
            throw new InvalidOperationException($"Scaleway delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task EnsureTokenAsync(string token, CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/dns-zones",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 401 or 403 ||
            body.Contains("denied_authentication", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Scaleway API token is not correct.");
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Scaleway list DNS zones failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<string> ResolveZoneAsync(
        string token,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/dns-zones/{Uri.EscapeDataString(candidate)}/records",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is 404 ||
                body.Contains("subdomain not found", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (status is >= 200 and < 300)
            {
                return candidate;
            }

            if (status is >= 400 and < 500)
            {
                continue;
            }

            throw new InvalidOperationException($"Scaleway get zone records failed ({status}): {TrimBody(body)}");
        }

        throw new InvalidOperationException($"Scaleway could not find a DNS zone for '{recordName}'.");
    }

    private static async Task<bool> HasTxtAsync(
        string token,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var page = 1;
        while (true)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/dns-zones/{Uri.EscapeDataString(zone)}/records?page={page}&per_page=100",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Scaleway list records failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            var matched = false;
            var count = 0;
            if (doc.RootElement.TryGetProperty("records", out var records) && records.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in records.EnumerateArray())
                {
                    count++;
                    var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                    var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                    var data = record.TryGetProperty("data", out var dataElement) ? dataElement.GetString() : null;
                    var normalized = NormalizeHost(name ?? string.Empty);
                    if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                        (string.Equals(normalized, relativeName, StringComparison.Ordinal) ||
                         string.Equals(normalized, $"{relativeName}.{zone}", StringComparison.Ordinal) ||
                         (relativeName.Length == 0 && (normalized.Length == 0 || string.Equals(normalized, zone, StringComparison.Ordinal)))) &&
                        string.Equals(UnquoteTxt(data ?? string.Empty), txtValue, StringComparison.Ordinal))
                    {
                        matched = true;
                    }
                }
            }

            if (matched)
            {
                return true;
            }

            var total = doc.RootElement.TryGetProperty("total_count", out var totalElement) && totalElement.TryGetInt32(out var totalCount)
                ? totalCount
                : page * 100;
            if (page * 100 >= total || count == 0)
            {
                return false;
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
        request.Headers.TryAddWithoutValidation("x-auth-token", token);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-ScalewayDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (body.Contains("denied_authentication", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Scaleway API token is not correct.");
        }

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
