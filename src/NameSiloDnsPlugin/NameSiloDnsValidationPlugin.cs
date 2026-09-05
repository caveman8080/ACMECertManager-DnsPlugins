using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text.Json;

namespace NameSiloDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class NameSiloDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://www.namesilo.com/api";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public NameSiloDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public NameSiloDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "namesilo",
        DisplayName = "NameSilo",
        Description = "DNS-01 via the NameSilo HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "NameSilo API key (Namesilo_Key)"
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

        if (await FindRecordIdAsync(apiKey, zone, relative, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        var (status, body, code) = await GetAsync(
            "dnsAddRecord",
            apiKey,
            [
                ("domain", zone),
                ("rrtype", "TXT"),
                ("rrhost", relative),
                ("rrvalue", request.TxtValue),
                ("rrttl", "3600")
            ],
            cancellationToken).ConfigureAwait(false);

        if (IsApiSuccess(status, code) || IsAlreadyExists(body, code))
        {
            return;
        }

        ThrowIfAuthFailed(status, body, code);
        throw new InvalidOperationException($"NameSilo add TXT failed ({status}, {code}): {TrimBody(body)}");
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
        var recordId = await FindRecordIdAsync(apiKey, zone, relative, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body, code) = await GetAsync(
            "dnsDeleteRecord",
            apiKey,
            [("domain", zone), ("rrid", recordId)],
            cancellationToken).ConfigureAwait(false);

        if (IsApiSuccess(status, code) || status is 404 || code is 280)
        {
            return;
        }

        ThrowIfAuthFailed(status, body, code);
        throw new InvalidOperationException($"NameSilo delete TXT failed ({status}, {code}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body, code) = await GetAsync("listDomains", apiKey, [], cancellationToken).ConfigureAwait(false);
        ThrowIfAuthFailed(status, body, code);
        if (!IsApiSuccess(status, code))
        {
            throw new InvalidOperationException($"NameSilo list domains failed ({status}, {code}): {TrimBody(body)}");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        using (var doc = JsonDocument.Parse(body))
        {
            foreach (var name in CollectDomainNames(doc.RootElement))
            {
                names.Add(NormalizeHost(name));
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            if (names.Contains(candidate))
            {
                return candidate;
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            var (probeStatus, probeBody, probeCode) = await GetAsync(
                "dnsListRecords",
                apiKey,
                [("domain", candidate)],
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(probeStatus, probeBody, probeCode);
            if (IsApiSuccess(probeStatus, probeCode))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"NameSilo could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string apiKey,
        string zone,
        string relativeName,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body, code) = await GetAsync(
            "dnsListRecords",
            apiKey,
            [("domain", zone)],
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body, code);
        if (!IsApiSuccess(status, code))
        {
            throw new InvalidOperationException($"NameSilo list records failed ({status}, {code}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        foreach (var record in EnumerateRecords(doc.RootElement))
        {
            var type = ReadString(record, "type");
            var host = ReadString(record, "host") ?? string.Empty;
            var value = UnquoteTxt(ReadString(record, "value") ?? string.Empty);
            var id = ReadString(record, "record_id");
            var normalizedHost = NormalizeHost(host);
            if (normalizedHost == "@")
            {
                normalizedHost = "";
            }

            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(normalizedHost, relativeName, StringComparison.Ordinal) ||
                 string.Equals(normalizedHost, recordName, StringComparison.Ordinal) ||
                 string.Equals(normalizedHost, $"{relativeName}.{zone}", StringComparison.Ordinal) ||
                 (relativeName.Length == 0 && (normalizedHost.Length == 0 || string.Equals(normalizedHost, zone, StringComparison.Ordinal)))) &&
                string.Equals(value, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body, int Code)> GetAsync(
        string operation,
        string apiKey,
        (string Name, string Value)[] extra,
        CancellationToken cancellationToken)
    {
        var query = new List<string>
        {
            "version=1",
            "type=json",
            $"key={Uri.EscapeDataString(apiKey)}"
        };
        foreach (var (name, value) in extra)
        {
            query.Add($"{Uri.EscapeDataString(name)}={Uri.EscapeDataString(value)}");
        }

        var url = $"{ApiBase}/{operation}?{string.Join("&", query)}";
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NameSiloDnsPlugin");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body, ReadReplyCode(body));
    }

    private static void ThrowIfAuthFailed(int status, string body, int code)
    {
        if (status is 401 or 403 || code is >= 110 and <= 115)
        {
            throw new InvalidOperationException(
                $"NameSilo authentication/authorization failed ({status}, {code}): {TrimBody(body)}");
        }
    }

    private static bool IsApiSuccess(int status, int code) =>
        status is >= 200 and < 300 && code is >= 300 and < 400;

    private static bool IsAlreadyExists(string body, int code) =>
        code is 280 &&
        (body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
         body.Contains("duplicate", StringComparison.OrdinalIgnoreCase));

    private static int ReadReplyCode(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var reply = doc.RootElement;
            if (reply.TryGetProperty("reply", out var nested))
            {
                reply = nested;
            }

            return ReadInt(reply, "code") ?? 0;
        }
        catch (JsonException)
        {
            return 0;
        }
    }

    private static IEnumerable<JsonElement> EnumerateRecords(JsonElement root)
    {
        var reply = root.TryGetProperty("reply", out var nested) ? nested : root;
        if (!reply.TryGetProperty("resource_record", out var records))
        {
            yield break;
        }

        if (records.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in records.EnumerateArray())
            {
                yield return item;
            }
        }
        else if (records.ValueKind == JsonValueKind.Object)
        {
            yield return records;
        }
    }

    private static IEnumerable<string> CollectDomainNames(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                var text = element.GetString();
                if (!string.IsNullOrWhiteSpace(text) && text.Contains('.') && text.Any(char.IsLetter))
                {
                    yield return text;
                }

                yield break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    foreach (var nested in CollectDomainNames(item))
                    {
                        yield return nested;
                    }
                }

                yield break;
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (property.NameEquals("code") || property.NameEquals("detail") || property.NameEquals("request"))
                    {
                        continue;
                    }

                    foreach (var nested in CollectDomainNames(property.Value))
                    {
                        yield return nested;
                    }
                }

                yield break;
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
