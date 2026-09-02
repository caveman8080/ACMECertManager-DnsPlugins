using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace EasyDnsDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class EasyDnsDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://rest.easydns.net";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public EasyDnsDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public EasyDnsDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "easydns",
        DisplayName = "EasyDNS",
        Description = "DNS-01 via the EasyDNS REST HTTP API using an API token and key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "EasyDNS API token (EASYDNS_Token)"
        },
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "EasyDNS API key (EASYDNS_Key)"
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
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existingId = await FindRecordIdAsync(token, apiKey, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            host = relative,
            rdata = request.TxtValue
        });

        var (status, body) = await SendAsync(
            HttpMethod.Put,
            $"{ApiBase}/zones/records/add/{Uri.EscapeDataString(zone)}/TXT",
            token,
            apiKey,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300)
        {
            return;
        }

        if (body.Contains("Record already exists", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException($"EasyDNS add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "apiToken");
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(token, apiKey, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/zones/records/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(recordId)}",
            token,
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 200 or 204 or 404 || HasStatus(body, 200))
        {
            return;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"EasyDNS delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private async Task<string> ResolveZoneAsync(
        string token,
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/zones/records/all/{Uri.EscapeDataString(candidate)}",
                token,
                apiKey,
                content: null,
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(status, body);

            if (status is 404)
            {
                continue;
            }

            if (HasStatus(body, 200))
            {
                return candidate;
            }

            if (status is >= 400 and < 500)
            {
                continue;
            }

            if (status is < 200 or >= 300)
            {
                continue;
            }
        }

        throw new InvalidOperationException($"EasyDNS could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string token,
        string apiKey,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var searchUrl = string.IsNullOrEmpty(relativeName)
            ? $"{ApiBase}/zones/records/all/{Uri.EscapeDataString(zone)}"
            : $"{ApiBase}/zones/records/all/{Uri.EscapeDataString(zone)}/search/{Uri.EscapeDataString(relativeName)}";

        var (status, body) = await SendAsync(
            HttpMethod.Get,
            searchUrl,
            token,
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300 && !HasStatus(body, 200))
        {
            throw new InvalidOperationException($"EasyDNS list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in data.EnumerateArray())
        {
            var type = ReadString(record, "type") ?? ReadString(record, "Type");
            var host = ReadString(record, "host") ?? ReadString(record, "Host") ?? string.Empty;
            var rdata = ReadString(record, "rdata") ?? ReadString(record, "rData") ?? string.Empty;
            var id = ReadId(record, "id") ?? ReadId(record, "Id");
            var normalizedHost = NormalizeHost(host);
            if (normalizedHost == "@")
            {
                normalizedHost = "";
            }

            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(normalizedHost, relativeName, StringComparison.Ordinal) ||
                 string.Equals(normalizedHost, $"{relativeName}.{zone}", StringComparison.Ordinal) ||
                 (relativeName.Length == 0 && (normalizedHost.Length == 0 || string.Equals(normalizedHost, zone, StringComparison.Ordinal)))) &&
                string.Equals(UnquoteTxt(rdata), txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string token,
        string apiKey,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{token}:{apiKey}"));
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {basic}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-EasyDnsDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (status is 401 or 403 || HasStatus(body, 401) || HasStatus(body, 403))
        {
            throw new InvalidOperationException(
                $"EasyDNS authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool HasStatus(string body, int expected) =>
        body.Contains($"\"status\":{expected}", StringComparison.Ordinal) ||
        body.Contains($"\"status\": {expected}", StringComparison.Ordinal);

    private static string? ReadString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetString() : null;

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
