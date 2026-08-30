using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text.Json;

namespace CloudnsDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class CloudnsDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.cloudns.net";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "cloudns",
        DisplayName = "ClouDNS",
        Description = "DNS-01 via the ClouDNS HTTP API using auth ID (or sub-auth ID) and password."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "authId",
            Label = "Auth ID",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Regular API auth ID (if not using sub-auth ID)"
        },
        new DnsCredentialField
        {
            Name = "subAuthId",
            Label = "Sub-auth ID",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional sub-auth ID; used instead of Auth ID when set"
        },
        new DnsCredentialField
        {
            Name = "authPassword",
            Label = "Auth Password",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "ClouDNS API password"
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
        var auth = GetAuthQuery(credentials);
        await LoginAsync(auth, cancellationToken).ConfigureAwait(false);

        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(auth, recordName, cancellationToken).ConfigureAwait(false);
        var host = GetRelativeName(recordName, zone.Name);

        var existingId = await FindRecordIdAsync(auth, zone.ApiName, host, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var (status, body) = await GetAsync(
            "dns/add-record.json",
            auth +
            $"&domain-name={Uri.EscapeDataString(zone.ApiName)}" +
            "&record-type=TXT" +
            $"&host={Uri.EscapeDataString(host)}" +
            $"&record={Uri.EscapeDataString(request.TxtValue)}" +
            "&ttl=60",
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300 || !IsSuccess(body))
        {
            throw new InvalidOperationException($"ClouDNS add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var auth = GetAuthQuery(credentials);
        await LoginAsync(auth, cancellationToken).ConfigureAwait(false);

        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(auth, recordName, cancellationToken).ConfigureAwait(false);
        var host = GetRelativeName(recordName, zone.Name);
        var recordId = await FindRecordIdAsync(auth, zone.ApiName, host, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await GetAsync(
            "dns/delete-record.json",
            auth +
            $"&domain-name={Uri.EscapeDataString(zone.ApiName)}" +
            $"&record-id={Uri.EscapeDataString(recordId)}",
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && (status is < 200 or >= 300 || !IsSuccess(body)))
        {
            throw new InvalidOperationException($"ClouDNS delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task LoginAsync(string auth, CancellationToken cancellationToken)
    {
        var (status, body) = await GetAsync("dns/login.json", auth, cancellationToken).ConfigureAwait(false);
        if (status is < 200 or >= 300 || !IsSuccess(body))
        {
            throw new InvalidOperationException($"ClouDNS login failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(string ApiName, string Name)> ResolveZoneAsync(
        string auth,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await GetAsync(
                "dns/get-zone-info.json",
                auth + $"&domain-name={Uri.EscapeDataString(candidate)}",
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300 || IsFailed(body))
            {
                continue;
            }

            using var doc = JsonDocument.Parse(body);
            var type = doc.RootElement.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            if (!string.IsNullOrWhiteSpace(type) &&
                type.Contains("cloud", StringComparison.OrdinalIgnoreCase) &&
                doc.RootElement.TryGetProperty("cloud-master", out var masterElement))
            {
                var master = masterElement.GetString();
                if (!string.IsNullOrWhiteSpace(master))
                {
                    return (NormalizeHost(master), candidate);
                }
            }

            return (candidate, candidate);
        }

        throw new InvalidOperationException($"ClouDNS could not find a zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string auth,
        string zone,
        string host,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await GetAsync(
            "dns/records.json",
            auth +
            $"&domain-name={Uri.EscapeDataString(zone)}" +
            $"&host={Uri.EscapeDataString(host)}" +
            "&type=TXT",
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"ClouDNS list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var property in doc.RootElement.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var record = property.Value;
            var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            var recordHost = record.TryGetProperty("host", out var hostElement) ? hostElement.GetString() : null;
            var value = record.TryGetProperty("record", out var valueElement) ? valueElement.GetString() : null;
            var id = ReadId(record, "id") ?? property.Name;
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(NormalizeHost(recordHost ?? string.Empty), host, StringComparison.Ordinal) &&
                string.Equals(UnquoteTxt(value ?? string.Empty), txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private static async Task<(int Status, string Body)> GetAsync(
        string endpoint,
        string query,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{ApiBase}/{endpoint}?{query}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-CloudnsDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static string GetAuthQuery(IReadOnlyDictionary<string, string> credentials)
    {
        var password = GetRequired(credentials, "authPassword");
        var subAuthId = GetOptional(credentials, "subAuthId");
        var authId = GetOptional(credentials, "authId");
        if (!string.IsNullOrWhiteSpace(subAuthId))
        {
            return $"sub-auth-id={Uri.EscapeDataString(subAuthId)}&auth-password={Uri.EscapeDataString(password)}";
        }

        if (!string.IsNullOrWhiteSpace(authId))
        {
            return $"auth-id={Uri.EscapeDataString(authId)}&auth-password={Uri.EscapeDataString(password)}";
        }

        throw new InvalidOperationException("Missing required credential 'authId' or 'subAuthId'.");
    }

    private static bool IsSuccess(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("status", out var status) &&
                   string.Equals(status.GetString(), "Success", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return body.Contains("\"status\":\"Success\"", StringComparison.OrdinalIgnoreCase);
        }
    }

    private static bool IsFailed(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("status", out var status) &&
                   string.Equals(status.GetString(), "Failed", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return body.Contains("\"status\":\"Failed\"", StringComparison.OrdinalIgnoreCase);
        }
    }

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
