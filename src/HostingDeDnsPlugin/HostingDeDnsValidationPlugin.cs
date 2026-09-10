using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace HostingDeDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class HostingDeDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://secure.hosting.de/api/dns/v1/json";
    private const int TxtTtl = 60;
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public HostingDeDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public HostingDeDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "hostingde",
        DisplayName = "hosting.de",
        Description = "DNS-01 via the hosting.de DNS JSON HTTP API using an auth token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "authToken",
            Label = "Auth Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "hosting.de API token (HOSTINGDE_APIKEY)"
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
        var authToken = GetRequired(credentials, "authToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(authToken, recordName, cancellationToken).ConfigureAwait(false);

        if (await FindRecordIdAsync(authToken, zone, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        var (status, body) = await CallAsync(
            "zoneUpdate",
            new Dictionary<string, object?>
            {
                ["authToken"] = authToken,
                ["zoneConfig"] = DeserializeObject(zone.ConfigJson),
                ["recordsToAdd"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["name"] = recordName,
                        ["type"] = "TXT",
                        ["content"] = QuoteTxt(request.TxtValue),
                        ["ttl"] = TxtTtl
                    }
                }
            },
            cancellationToken).ConfigureAwait(false);

        if (IsApiSuccess(status, body) || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"hosting.de add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var authToken = GetRequired(credentials, "authToken");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(authToken, recordName, cancellationToken).ConfigureAwait(false);
        var recordId = await FindRecordIdAsync(authToken, zone, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await CallAsync(
            "zoneUpdate",
            new Dictionary<string, object?>
            {
                ["authToken"] = authToken,
                ["zoneConfig"] = DeserializeObject(zone.ConfigJson),
                ["recordsToDelete"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["id"] = recordId
                    }
                }
            },
            cancellationToken).ConfigureAwait(false);

        if (IsApiSuccess(status, body) || status is 404)
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"hosting.de delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<Zone> ResolveZoneAsync(
        string authToken,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await CallAsync(
                "zoneConfigsFind",
                new Dictionary<string, object?>
                {
                    ["authToken"] = authToken,
                    ["filter"] = new Dictionary<string, object?>
                    {
                        ["field"] = "ZoneName",
                        ["value"] = candidate
                    },
                    ["limit"] = 1
                },
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(status, body);

            if (!IsApiSuccess(status, body))
            {
                continue;
            }

            foreach (var item in EnumerateData(body))
            {
                var name = ReadString(item, "name") ?? ReadString(item, "nameUnicode") ?? string.Empty;
                var id = ReadId(item, "id");
                var type = ReadString(item, "type");
                if (string.IsNullOrWhiteSpace(id) ||
                    !string.Equals(NormalizeHost(name), candidate, StringComparison.Ordinal))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(type) &&
                    !string.Equals(type, "NATIVE", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return new Zone(id, candidate, item.GetRawText());
            }
        }

        throw new InvalidOperationException($"hosting.de could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string authToken,
        Zone zone,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await CallAsync(
            "recordsFind",
            new Dictionary<string, object?>
            {
                ["authToken"] = authToken,
                ["filter"] = new Dictionary<string, object?>
                {
                    ["subFilterConnective"] = "AND",
                    ["subFilter"] = new object[]
                    {
                        new Dictionary<string, object?> { ["field"] = "ZoneConfigId", ["value"] = zone.Id },
                        new Dictionary<string, object?> { ["field"] = "RecordName", ["value"] = recordName },
                        new Dictionary<string, object?> { ["field"] = "RecordType", ["value"] = "TXT" }
                    }
                }
            },
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return null;
        }

        ThrowIfAuthFailed(status, body);
        if (!IsApiSuccess(status, body))
        {
            throw new InvalidOperationException($"hosting.de list records failed ({status}): {TrimBody(body)}");
        }

        foreach (var record in EnumerateData(body))
        {
            var type = ReadString(record, "type");
            var name = NormalizeHost(ReadString(record, "name") ?? string.Empty);
            var content = UnquoteTxt(ReadString(record, "content") ?? string.Empty);
            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesMatch(name, recordName, zone.Name) &&
                string.Equals(content, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body)> CallAsync(
        string action,
        Dictionary<string, object?> payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/{action}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-HostingDeDnsPlugin");
        request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static void ThrowIfAuthFailed(int status, string body)
    {
        if (!IsAuthFailure(status, body))
        {
            return;
        }

        throw new InvalidOperationException(
            $"hosting.de authentication/authorization failed ({status}): {TrimBody(body)}");
    }

    private static bool IsAuthFailure(int status, string body)
    {
        if (status is 401 or 403)
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
                var code = ReadInt(error, "code");
                if (code is 10101 or 10102 or 10109)
                {
                    return true;
                }

                var context = ReadString(error, "context") ?? string.Empty;
                if (context.Contains("authToken", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                var text = (ReadString(error, "text") ?? string.Empty) + " " + (ReadString(error, "value") ?? string.Empty);
                if (text.Contains("API key", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("API-Key", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("invalid token", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("authentication", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("authorization", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch (JsonException)
        {
            // Fall through.
        }

        return false;
    }

    private static bool IsApiSuccess(int status, string body)
    {
        if (status is < 200 or >= 300)
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var apiStatus = ReadString(doc.RootElement, "status");
            if (string.IsNullOrWhiteSpace(apiStatus))
            {
                return true;
            }

            return string.Equals(apiStatus, "success", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(apiStatus, "pending", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return true;
        }
    }

    private static bool IsAlreadyExists(string body) =>
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("already_exists", StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<JsonElement> EnumerateData(string body)
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
            JsonElement data;
            if (doc.RootElement.TryGetProperty("response", out var response) &&
                response.ValueKind == JsonValueKind.Object &&
                response.TryGetProperty("data", out data))
            {
                // keep going
            }
            else if (doc.RootElement.TryGetProperty("data", out data))
            {
                // keep going
            }
            else
            {
                yield break;
            }

            if (data.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in data.EnumerateArray())
                {
                    yield return item.Clone();
                }
            }
            else if (data.ValueKind == JsonValueKind.Object)
            {
                yield return data.Clone();
            }
        }
    }

    private static bool NamesMatch(string name, string recordName, string zone)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        return string.Equals(name, recordName, StringComparison.Ordinal) ||
               string.Equals(name, $"{recordName}.{zone}", StringComparison.Ordinal) ||
               string.Equals($"{name}.{zone}", recordName, StringComparison.Ordinal);
    }

    private static object? DeserializeObject(string json)
    {
        return JsonSerializer.Deserialize<object>(json);
    }

    private static string QuoteTxt(string value)
    {
        var unquoted = UnquoteTxt(value);
        return $"\"{unquoted}\"";
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
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    private static int? ReadInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt32(out var n) => n,
            JsonValueKind.String when int.TryParse(value.GetString(), out var n) => n,
            _ => null
        };
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

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }

    private sealed record Zone(string Id, string Name, string ConfigJson);
}
