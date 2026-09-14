using ACMECertManager;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace NoIpDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class NoIpDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.noip.com/v1";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public NoIpDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public NoIpDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "noip",
        DisplayName = "No-IP",
        Description = "DNS-01 via the No-IP HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "No-IP API key from the API Key management page"
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
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var payload = JsonSerializer.Serialize(new[]
        {
            new { value = request.TxtValue }
        });

        var path = $"dns/records/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(relative)}/rrsets/TXT/rdata";
        var (status, body) = await SendAsync(HttpMethod.Post, apiKey, path, payload, cancellationToken).ConfigureAwait(false);
        if (status is 409 || body.Contains("already exists", StringComparison.OrdinalIgnoreCase))
        {
            await PublishNameAsync(apiKey, zone, relative, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (status is < 200 or >= 300)
        {
            ThrowIfAuthFailed(status, body);
            throw new InvalidOperationException($"No-IP add TXT failed ({status}): {TrimBody(body)}");
        }

        await PublishNameAsync(apiKey, zone, relative, cancellationToken).ConfigureAwait(false);
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var path = $"dns/records/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(relative)}/rrsets/TXT";
        var (status, body) = await SendAsync(HttpMethod.Get, apiKey, path, payload: null, cancellationToken).ConfigureAwait(false);
        if (status is 404)
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"No-IP list TXT failed ({status}): {TrimBody(body)}");
        }

        foreach (var (value, label) in EnumerateRdata(body))
        {
            if (!string.Equals(UnquoteTxt(value), request.TxtValue, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(label))
            {
                continue;
            }

            var deletePath =
                $"dns/records/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(relative)}/rrsets/TXT/rdata/{Uri.EscapeDataString(label)}";
            var (deleteStatus, deleteBody) = await SendAsync(
                HttpMethod.Delete,
                apiKey,
                deletePath,
                payload: null,
                cancellationToken).ConfigureAwait(false);
            if (deleteStatus is >= 200 and < 300 or 404)
            {
                continue;
            }

            ThrowIfAuthFailed(deleteStatus, deleteBody);
            throw new InvalidOperationException($"No-IP delete TXT failed ({deleteStatus}): {TrimBody(deleteBody)}");
        }
    }

    private async Task PublishNameAsync(
        string apiKey,
        string zone,
        string relative,
        CancellationToken cancellationToken)
    {
        var path = $"dns/records/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(relative)}/publish";
        var (status, body) = await SendAsync(HttpMethod.Post, apiKey, path, payload: null, cancellationToken)
            .ConfigureAwait(false);
        if (status is >= 200 and < 300 or 404)
        {
            return;
        }

        // Already published / not required for this name.
        if (status is 403 or 409)
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"No-IP publish name failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        int? authStatus = null;
        string authBody = string.Empty;

        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                apiKey,
                $"dns/zones/{Uri.EscapeDataString(candidate)}",
                payload: null,
                cancellationToken).ConfigureAwait(false);

            if (status is 401 or 403)
            {
                authStatus = status;
                authBody = body;
                break;
            }

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        if (authStatus is not null)
        {
            throw new InvalidOperationException(
                $"No-IP authentication/authorization failed ({authStatus}): {TrimBody(authBody)}");
        }

        throw new InvalidOperationException($"No-IP could not find a zone for '{recordName}'.");
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string apiKey,
        string endpoint,
        string? payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, $"{ApiBase}/{endpoint}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NoIpDnsPlugin");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
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
                $"No-IP authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static IEnumerable<(string Value, string Label)> EnumerateRdata(string body)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            yield break;
        }

        using (doc)
        {
            if (!doc.RootElement.TryGetProperty("data", out var data))
            {
                yield break;
            }

            JsonElement rdata;
            if (data.ValueKind == JsonValueKind.Object && data.TryGetProperty("rdata", out rdata) &&
                rdata.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in rdata.EnumerateArray())
                {
                    var value = ReadString(item, "value") ?? string.Empty;
                    var label = ReadString(item, "label") ?? string.Empty;
                    yield return (value, label);
                }
            }
        }
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
