using ACMECertManager;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace HostingerDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class HostingerDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://developers.hostinger.com/api/dns/v1/zones";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public HostingerDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public HostingerDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "hostinger",
        DisplayName = "Hostinger",
        Description = "DNS-01 via the Hostinger HTTP API using a bearer API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Hostinger API token (HOSTINGER_Token)"
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
        var apiToken = GetRequired(credentials, "apiToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiToken, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var payload = JsonSerializer.Serialize(new
        {
            overwrite = false,
            zone = new[]
            {
                new
                {
                    name = relative,
                    records = new[] { new { content = request.TxtValue } },
                    type = "TXT",
                    ttl = 120
                }
            }
        });

        var (status, body) = await SendAsync(
            HttpMethod.Put,
            apiToken,
            Uri.EscapeDataString(zone),
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Hostinger add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiToken = GetRequired(credentials, "apiToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiToken, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var (status, body) = await SendAsync(
            HttpMethod.Get,
            apiToken,
            Uri.EscapeDataString(zone),
            payload: null,
            cancellationToken).ConfigureAwait(false);
        ThrowIfAuthFailed(status, body);
        if (status is 404)
        {
            return;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Hostinger list records failed ({status}): {TrimBody(body)}");
        }

        var remaining = FindRemainingTxt(body, relative, request.TxtValue);
        if (remaining is null)
        {
            return;
        }

        if (remaining.Count > 0)
        {
            var payload = JsonSerializer.Serialize(new
            {
                overwrite = true,
                zone = new[]
                {
                    new
                    {
                        name = relative,
                        records = remaining.Select(content => new { content }).ToArray(),
                        type = "TXT",
                        ttl = 120
                    }
                }
            });

            var (putStatus, putBody) = await SendAsync(
                HttpMethod.Put,
                apiToken,
                Uri.EscapeDataString(zone),
                payload,
                cancellationToken).ConfigureAwait(false);
            if (putStatus is >= 200 and < 300)
            {
                return;
            }

            ThrowIfAuthFailed(putStatus, putBody);
            throw new InvalidOperationException($"Hostinger update TXT failed ({putStatus}): {TrimBody(putBody)}");
        }

        var deletePayload = JsonSerializer.Serialize(new
        {
            filters = new[]
            {
                new { name = relative, type = "TXT" }
            }
        });

        var (deleteStatus, deleteBody) = await SendAsync(
            HttpMethod.Delete,
            apiToken,
            Uri.EscapeDataString(zone),
            deletePayload,
            cancellationToken).ConfigureAwait(false);
        if (deleteStatus is >= 200 and < 300 or 404)
        {
            return;
        }

        ThrowIfAuthFailed(deleteStatus, deleteBody);
        throw new InvalidOperationException($"Hostinger delete TXT failed ({deleteStatus}): {TrimBody(deleteBody)}");
    }

    private async Task<string> ResolveZoneAsync(
        string apiToken,
        string recordName,
        CancellationToken cancellationToken)
    {
        int? authStatus = null;
        string authBody = string.Empty;

        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                apiToken,
                Uri.EscapeDataString(candidate),
                payload: null,
                cancellationToken).ConfigureAwait(false);

            if (status is 401 or 403)
            {
                authStatus = status;
                authBody = body;
                break;
            }

            if (status is >= 200 and < 300 && LooksLikeZone(body))
            {
                return candidate;
            }
        }

        if (authStatus is not null)
        {
            throw new InvalidOperationException(
                $"Hostinger authentication/authorization failed ({authStatus}): {TrimBody(authBody)}");
        }

        throw new InvalidOperationException($"Hostinger could not find a zone for '{recordName}'.");
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string apiToken,
        string endpoint,
        string? payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, $"{ApiBase}/{endpoint}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-HostingerDnsPlugin");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
        if (payload is not null)
        {
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (status is 401 or 403)
        {
            throw new InvalidOperationException(
                $"Hostinger authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsAlreadyExists(string body) =>
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("conflicts with another resource record", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("DNS:4008", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeZone(string body)
    {
        var trimmed = body.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed == "[]")
        {
            return false;
        }

        return trimmed.Contains("\"records\"", StringComparison.OrdinalIgnoreCase) ||
               trimmed.Contains("\"type\"", StringComparison.OrdinalIgnoreCase);
    }

    private static List<string>? FindRemainingTxt(string body, string relative, string txtValue)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            return null;
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var set in doc.RootElement.EnumerateArray())
            {
                var name = ReadString(set, "name") ?? string.Empty;
                var type = ReadString(set, "type") ?? string.Empty;
                if (!string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) ||
                    !NamesMatch(name, relative))
                {
                    continue;
                }

                if (!set.TryGetProperty("records", out var records) || records.ValueKind != JsonValueKind.Array)
                {
                    return [];
                }

                var remaining = new List<string>();
                foreach (var record in records.EnumerateArray())
                {
                    var content = UnquoteTxt(ReadString(record, "content") ?? string.Empty);
                    if (!string.Equals(content, txtValue, StringComparison.Ordinal))
                    {
                        remaining.Add(ReadString(record, "content") ?? content);
                    }
                }

                return remaining;
            }
        }

        return null;
    }

    private static string? ReadString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null
        };
    }

    private static bool NamesMatch(string name, string relative)
    {
        var normalizedName = NormalizeHost(name);
        var normalizedRelative = NormalizeHost(relative);
        if (normalizedName is "@" or "")
        {
            return normalizedRelative is "@" or "";
        }

        return string.Equals(normalizedName, normalizedRelative, StringComparison.Ordinal);
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
