using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace NjallaDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class NjallaDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiUrl = "https://njal.la/api/1/";
    private const int TxtTtl = 120;
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public NjallaDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public NjallaDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "njalla",
        DisplayName = "Njalla",
        Description = "DNS-01 via the Njalla JSON-RPC HTTP API using an API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Njalla API token (NJALLA_Token)"
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

        if (await FindRecordIdAsync(apiToken, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        var (status, body, errorCode, errorMessage) = await CallAsync(
            apiToken,
            "add-record",
            new Dictionary<string, object?>
            {
                ["domain"] = zone,
                ["type"] = "TXT",
                ["name"] = relative,
                ["content"] = request.TxtValue,
                ["ttl"] = TxtTtl
            },
            cancellationToken).ConfigureAwait(false);

        if (IsRpcSuccess(status, errorCode, errorMessage) || IsAlreadyExists(body, errorMessage))
        {
            return;
        }

        ThrowIfAuthFailed(status, body, errorCode, errorMessage);
        throw new InvalidOperationException($"Njalla add TXT failed ({status}): {TrimBody(body)}");
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
        var recordId = await FindRecordIdAsync(apiToken, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var parameters = new Dictionary<string, object?> { ["domain"] = zone };
        if (long.TryParse(recordId, out var numericId))
        {
            parameters["id"] = numericId;
        }
        else
        {
            parameters["id"] = recordId;
        }

        var (status, body, errorCode, errorMessage) = await CallAsync(
            apiToken,
            "remove-record",
            parameters,
            cancellationToken).ConfigureAwait(false);

        if (IsRpcSuccess(status, errorCode, errorMessage) || IsNotFound(status, errorCode, errorMessage, body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body, errorCode, errorMessage);
        throw new InvalidOperationException($"Njalla delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string apiToken,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body, errorCode, errorMessage) = await CallAsync(
                apiToken,
                "get-domain",
                new Dictionary<string, object?> { ["domain"] = candidate },
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(status, body, errorCode, errorMessage);

            if (IsNotFound(status, errorCode, errorMessage, body) || IsPermissionDenied(errorMessage, body))
            {
                continue;
            }

            if (!IsRpcSuccess(status, errorCode, errorMessage))
            {
                continue;
            }

            if (DomainMatches(body, candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"Njalla could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string apiToken,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body, errorCode, errorMessage) = await CallAsync(
            apiToken,
            "list-records",
            new Dictionary<string, object?> { ["domain"] = zone },
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body, errorCode, errorMessage);
        if (IsNotFound(status, errorCode, errorMessage, body))
        {
            return null;
        }

        if (!IsRpcSuccess(status, errorCode, errorMessage))
        {
            throw new InvalidOperationException($"Njalla list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("result", out var result))
        {
            return null;
        }

        JsonElement records = result;
        if (result.ValueKind == JsonValueKind.Object &&
            result.TryGetProperty("records", out var wrapped) &&
            wrapped.ValueKind == JsonValueKind.Array)
        {
            records = wrapped;
        }

        if (records.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = ReadString(record, "type");
            var name = NormalizeHost(ReadString(record, "name") ?? string.Empty);
            var content = UnquoteTxt(ReadString(record, "content") ?? string.Empty);
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesMatch(name, relativeName, zone) &&
                string.Equals(content, txtValue, StringComparison.Ordinal))
            {
                var id = ReadId(record, "id");
                if (!string.IsNullOrWhiteSpace(id))
                {
                    return id;
                }
            }
        }

        return null;
    }

    private async Task<(int Status, string Body, int? ErrorCode, string? ErrorMessage)> CallAsync(
        string apiToken,
        string method,
        Dictionary<string, object?> parameters,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = method,
            ["params"] = parameters,
            ["id"] = "1"
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUrl);
        request.Headers.TryAddWithoutValidation("Authorization", $"Njalla {apiToken}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NjallaDnsPlugin");
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var (errorCode, errorMessage) = ReadRpcError(body);
        return ((int)response.StatusCode, body, errorCode, errorMessage);
    }

    private static void ThrowIfAuthFailed(int status, string body, int? errorCode, string? errorMessage)
    {
        if (status is 401 or 403 || IsAuthFailure(errorCode, errorMessage, body))
        {
            throw new InvalidOperationException(
                $"Njalla authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsAuthFailure(int? errorCode, string? errorMessage, string body) =>
        errorCode is 401 ||
        IsAuthMessage(errorMessage) ||
        IsAuthMessage(body);

    private static bool IsAuthMessage(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        return text.Contains("invalid token", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("unauthenticated", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("not authenticated", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("authentication", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRpcSuccess(int status, int? errorCode, string? errorMessage) =>
        status is >= 200 and < 300 && errorCode is null && string.IsNullOrWhiteSpace(errorMessage);

    private static bool IsAlreadyExists(string body, string? errorMessage) =>
        ContainsAny(errorMessage, "already exists", "already_exists") ||
        ContainsAny(body, "already exists", "already_exists");

    private static bool IsNotFound(int status, int? errorCode, string? errorMessage, string body) =>
        status is 404 ||
        errorCode is 404 ||
        ContainsAny(errorMessage, "not found", "unknown domain", "no such domain") ||
        ContainsAny(body, "not found", "unknown domain", "no such domain");

    private static bool IsPermissionDenied(string? errorMessage, string body) =>
        ContainsAny(errorMessage, "permission denied") ||
        ContainsAny(body, "permission denied");

    private static bool ContainsAny(string? text, params string[] needles)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        foreach (var needle in needles)
        {
            if (text.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool DomainMatches(string body, string candidate)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("result", out var result) ||
                result.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                return false;
            }

            if (result.ValueKind == JsonValueKind.Object)
            {
                var name = ReadString(result, "name");
                if (!string.IsNullOrWhiteSpace(name))
                {
                    return string.Equals(NormalizeHost(name), candidate, StringComparison.Ordinal);
                }
            }

            return true;
        }
        catch (JsonException)
        {
            return body.Contains($"\"{candidate}\"", StringComparison.OrdinalIgnoreCase);
        }
    }

    private static (int? Code, string? Message) ReadRpcError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("error", out var error) ||
                error.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                return (null, null);
            }

            if (error.ValueKind == JsonValueKind.String)
            {
                return (null, error.GetString());
            }

            if (error.ValueKind != JsonValueKind.Object)
            {
                return (null, error.GetRawText());
            }

            return (ReadInt(error, "code"), ReadString(error, "message") ?? ReadString(error, "error"));
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }

    private static bool NamesMatch(string name, string relative, string zone)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        return string.Equals(name, relative, StringComparison.Ordinal) ||
               string.Equals(name, $"{relative}.{zone}", StringComparison.Ordinal) ||
               (relative is "@" && (name is "@" || string.Equals(name, zone, StringComparison.Ordinal)));
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

    private static string? ReadId(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var id))
        {
            return null;
        }

        return id.ValueKind switch
        {
            JsonValueKind.String => id.GetString(),
            JsonValueKind.Number => id.GetRawText(),
            _ => null
        };
    }

    private static int? ReadInt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        if (value.ValueKind == JsonValueKind.String &&
            int.TryParse(value.GetString(), out var parsed))
        {
            return parsed;
        }

        return null;
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

    private static string UnquoteTxt(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
        {
            return trimmed[1..^1];
        }

        return trimmed;
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
