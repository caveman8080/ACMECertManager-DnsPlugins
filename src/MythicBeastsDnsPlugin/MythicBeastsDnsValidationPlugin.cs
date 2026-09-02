using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace MythicBeastsDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class MythicBeastsDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.mythic-beasts.com/dns/v2/zones";
    private const string AuthUrl = "https://auth.mythic-beasts.com/login";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public MythicBeastsDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public MythicBeastsDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "mythicbeasts",
        DisplayName = "Mythic Beasts",
        Description = "DNS-01 via the Mythic Beasts DNS HTTP API v2 using an OAuth2 API key and secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Mythic Beasts API key (MB_AK)"
        },
        new DnsCredentialField
        {
            Name = "apiSecret",
            Label = "API Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Mythic Beasts API secret (MB_AS)"
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
        var accessToken = await GetAccessTokenAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(accessToken, recordName, cancellationToken).ConfigureAwait(false);
        var relative = ToHost(GetRelativeName(recordName, zone));

        if (await HasTxtAsync(accessToken, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var (status, body) = await SendFormAsync(
            HttpMethod.Post,
            $"{ApiBase}/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(relative)}/TXT",
            accessToken,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300)
        {
            return;
        }

        if (body.Contains("records added", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("records_added", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("already exists", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException($"Mythic Beasts add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var accessToken = await GetAccessTokenAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(accessToken, recordName, cancellationToken).ConfigureAwait(false);
        var relative = ToHost(GetRelativeName(recordName, zone));

        if (!await HasTxtAsync(accessToken, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var url =
            $"{ApiBase}/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(relative)}/TXT" +
            $"?data={Uri.EscapeDataString(request.TxtValue)}";
        var (status, body) = await SendFormAsync(
            HttpMethod.Delete,
            url,
            accessToken,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || status is 404)
        {
            return;
        }

        if (body.Contains("records removed", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("records_removed", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("not found", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException($"Mythic Beasts delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> GetAccessTokenAsync(
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var apiSecret = GetRequired(credentials, "apiSecret");

        using var request = new HttpRequestMessage(HttpMethod.Post, AuthUrl);
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{apiKey}:{apiSecret}"));
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {basic}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-MythicBeastsDnsPlugin");
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials"
        });

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Mythic Beasts OAuth2 failed ({(int)response.StatusCode}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        var accessToken = doc.RootElement.TryGetProperty("access_token", out var tokenElement)
            ? tokenElement.GetString()
            : null;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new InvalidOperationException($"Mythic Beasts OAuth2 did not return an access token: {TrimBody(body)}");
        }

        return accessToken;
    }

    private async Task<string> ResolveZoneAsync(
        string accessToken,
        string recordName,
        CancellationToken cancellationToken)
    {
        var listed = await TryListZonesAsync(accessToken, cancellationToken).ConfigureAwait(false);
        if (listed is { Count: > 0 })
        {
            foreach (var candidate in CandidateZones(recordName))
            {
                if (listed.Contains(candidate))
                {
                    return candidate;
                }
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/{Uri.EscapeDataString(candidate)}/records",
                accessToken,
                cancellationToken).ConfigureAwait(false);

            if (status is 401)
            {
                throw new InvalidOperationException($"Mythic Beasts authentication failed ({status}): {TrimBody(body)}");
            }

            if (status is 403 or 404)
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

            throw new InvalidOperationException($"Mythic Beasts get zone records failed ({status}): {TrimBody(body)}");
        }

        throw new InvalidOperationException($"Mythic Beasts could not find a DNS zone for '{recordName}'.");
    }

    private async Task<HashSet<string>?> TryListZonesAsync(string accessToken, CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(HttpMethod.Get, ApiBase, accessToken, cancellationToken).ConfigureAwait(false);
        if (status is 401)
        {
            throw new InvalidOperationException($"Mythic Beasts authentication failed ({status}): {TrimBody(body)}");
        }

        if (status is < 200 or >= 300)
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var names = new HashSet<string>(StringComparer.Ordinal);
            if (doc.RootElement.TryGetProperty("zones", out var zones) && zones.ValueKind == JsonValueKind.Array)
            {
                foreach (var zone in zones.EnumerateArray())
                {
                    var name = zone.ValueKind == JsonValueKind.String
                        ? zone.GetString()
                        : zone.TryGetProperty("name", out var nameElement)
                            ? nameElement.GetString()
                            : null;
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        names.Add(NormalizeHost(name));
                    }
                }
            }

            return names;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private async Task<bool> HasTxtAsync(
        string accessToken,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(relativeName)}/TXT",
            accessToken,
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return false;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Mythic Beasts list TXT failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("records", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            var host = record.TryGetProperty("host", out var hostElement) ? hostElement.GetString() : null;
            var data = record.TryGetProperty("data", out var dataElement) ? dataElement.GetString() : null;
            var normalizedHost = NormalizeHost(host ?? string.Empty);
            if (normalizedHost == "@")
            {
                normalizedHost = "";
            }

            var expectedHost = relativeName == "@" ? "" : NormalizeHost(relativeName);
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(normalizedHost, expectedHost, StringComparison.Ordinal) &&
                string.Equals(UnquoteTxt(data ?? string.Empty), txtValue, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<(int Status, string Body)> SendFormAsync(
        HttpMethod method,
        string url,
        string accessToken,
        string txtValue,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {accessToken}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-MythicBeastsDnsPlugin");
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["data"] = txtValue
        });

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string accessToken,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {accessToken}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-MythicBeastsDnsPlugin");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
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

    private static string ToHost(string relative) => string.IsNullOrEmpty(relative) ? "@" : relative;

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
