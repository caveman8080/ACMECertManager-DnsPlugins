using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace NetcupDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class NetcupDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiUrl = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public NetcupDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public NetcupDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "netcup",
        DisplayName = "netcup",
        Description = "DNS-01 via the netcup CCP JSON HTTP API using customer number, API key, and API password."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "customerNumber",
            Label = "Customer Number",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "netcup customer number (NC_CID)"
        },
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "netcup API key (NC_Apikey)"
        },
        new DnsCredentialField
        {
            Name = "apiPassword",
            Label = "API Password",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "netcup API password (NC_Apipw)"
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
        var customerNumber = GetRequired(credentials, "customerNumber");
        var apiKey = GetRequired(credentials, "apiKey");
        var apiPassword = GetRequired(credentials, "apiPassword");
        var sessionId = await LoginAsync(customerNumber, apiKey, apiPassword, cancellationToken).ConfigureAwait(false);
        try
        {
            var recordName = NormalizeHost(request.RecordName);
            var zone = await ResolveZoneAsync(customerNumber, apiKey, sessionId, recordName, cancellationToken).ConfigureAwait(false);
            var relative = ToHost(GetRelativeName(recordName, zone));

            if (await FindRecordIdAsync(customerNumber, apiKey, sessionId, zone, relative, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false) is not null)
            {
                return;
            }

            var (status, body, code) = await CallAsync(
                "updateDnsRecords",
                new Dictionary<string, object?>
                {
                    ["customernumber"] = customerNumber,
                    ["apikey"] = apiKey,
                    ["apisessionid"] = sessionId,
                    ["domainname"] = zone,
                    ["dnsrecordset"] = new Dictionary<string, object?>
                    {
                        ["dnsrecords"] = new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["id"] = "",
                                ["hostname"] = relative,
                                ["type"] = "TXT",
                                ["priority"] = "",
                                ["destination"] = request.TxtValue,
                                ["deleterecord"] = false,
                                ["state"] = "yes"
                            }
                        }
                    }
                },
                cancellationToken).ConfigureAwait(false);

            if (IsApiSuccess(status, body) || code == 5029)
            {
                return;
            }

            throw new InvalidOperationException($"netcup add TXT failed ({status}, {code}): {TrimBody(body)}");
        }
        finally
        {
            await LogoutAsync(customerNumber, apiKey, sessionId, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var customerNumber = GetRequired(credentials, "customerNumber");
        var apiKey = GetRequired(credentials, "apiKey");
        var apiPassword = GetRequired(credentials, "apiPassword");
        var sessionId = await LoginAsync(customerNumber, apiKey, apiPassword, cancellationToken).ConfigureAwait(false);
        try
        {
            var recordName = NormalizeHost(request.RecordName);
            var zone = await ResolveZoneAsync(customerNumber, apiKey, sessionId, recordName, cancellationToken).ConfigureAwait(false);
            var relative = ToHost(GetRelativeName(recordName, zone));
            var recordId = await FindRecordIdAsync(customerNumber, apiKey, sessionId, zone, relative, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(recordId))
            {
                return;
            }

            var (status, body, code) = await CallAsync(
                "updateDnsRecords",
                new Dictionary<string, object?>
                {
                    ["customernumber"] = customerNumber,
                    ["apikey"] = apiKey,
                    ["apisessionid"] = sessionId,
                    ["domainname"] = zone,
                    ["dnsrecordset"] = new Dictionary<string, object?>
                    {
                        ["dnsrecords"] = new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["id"] = recordId,
                                ["hostname"] = relative,
                                ["type"] = "TXT",
                                ["priority"] = "",
                                ["destination"] = request.TxtValue,
                                ["deleterecord"] = true,
                                ["state"] = "yes"
                            }
                        }
                    }
                },
                cancellationToken).ConfigureAwait(false);

            if (IsApiSuccess(status, body) || code is 5028 or 5029)
            {
                return;
            }

            throw new InvalidOperationException($"netcup delete TXT failed ({status}, {code}): {TrimBody(body)}");
        }
        finally
        {
            await LogoutAsync(customerNumber, apiKey, sessionId, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<string> LoginAsync(
        string customerNumber,
        string apiKey,
        string apiPassword,
        CancellationToken cancellationToken)
    {
        var (status, body, code) = await CallAsync(
            "login",
            new Dictionary<string, object?>
            {
                ["customernumber"] = customerNumber,
                ["apikey"] = apiKey,
                ["apipassword"] = apiPassword
            },
            cancellationToken).ConfigureAwait(false);

        if (status is 401 or 403 || code is 4012 or 4013 or 4001)
        {
            throw new InvalidOperationException(
                $"netcup authentication/authorization failed ({status}, {code}): {TrimBody(body)}");
        }

        if (!IsApiSuccess(status, body))
        {
            throw new InvalidOperationException(
                $"netcup authentication/authorization failed ({status}, {code}): {TrimBody(body)}");
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("responsedata", out var data) &&
                data.ValueKind == JsonValueKind.Object)
            {
                var sessionId = ReadString(data, "apisessionid");
                if (!string.IsNullOrWhiteSpace(sessionId))
                {
                    return sessionId;
                }
            }
        }
        catch (JsonException)
        {
            // Fall through.
        }

        throw new InvalidOperationException($"netcup login did not return apisessionid: {TrimBody(body)}");
    }

    private async Task LogoutAsync(
        string customerNumber,
        string apiKey,
        string sessionId,
        CancellationToken cancellationToken)
    {
        try
        {
            await CallAsync(
                "logout",
                new Dictionary<string, object?>
                {
                    ["customernumber"] = customerNumber,
                    ["apikey"] = apiKey,
                    ["apisessionid"] = sessionId
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            // Best-effort logout.
        }
        catch (TaskCanceledException)
        {
            // Best-effort logout.
        }
    }

    private async Task<string> ResolveZoneAsync(
        string customerNumber,
        string apiKey,
        string sessionId,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body, code) = await CallAsync(
                "infoDnsRecords",
                new Dictionary<string, object?>
                {
                    ["customernumber"] = customerNumber,
                    ["apikey"] = apiKey,
                    ["apisessionid"] = sessionId,
                    ["domainname"] = candidate
                },
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(status, body, code);

            // 5028 = zone could not be found; 4013 = validation error on a non-zone name.
            if (code is 5028 or 4013)
            {
                continue;
            }

            // 5029 = zone exists but has no records — still the matching zone.
            if (IsApiSuccess(status, body) || code == 5029)
            {
                return candidate;
            }

            if (status is >= 400 and < 500)
            {
                continue;
            }
        }

        throw new InvalidOperationException($"netcup could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string customerNumber,
        string apiKey,
        string sessionId,
        string zone,
        string relativeName,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body, code) = await CallAsync(
            "infoDnsRecords",
            new Dictionary<string, object?>
            {
                ["customernumber"] = customerNumber,
                ["apikey"] = apiKey,
                ["apisessionid"] = sessionId,
                ["domainname"] = zone
            },
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body, code);

        if (code is 5028 or 5029)
        {
            return null;
        }

        if (!IsApiSuccess(status, body))
        {
            throw new InvalidOperationException($"netcup list records failed ({status}, {code}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        foreach (var record in EnumerateRecords(doc.RootElement))
        {
            var type = ReadString(record, "type");
            var hostname = ReadString(record, "hostname") ?? string.Empty;
            var destination = UnquoteTxt(ReadString(record, "destination") ?? string.Empty);
            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesMatch(hostname, relativeName, recordName, zone) &&
                string.Equals(destination, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body, int Code)> CallAsync(
        string action,
        Dictionary<string, object?> param,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["action"] = action,
            ["param"] = param
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUrl);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NetcupDnsPlugin");
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body, ReadStatusCode(body));
    }

    private static void ThrowIfAuthFailed(int status, string body, int code)
    {
        if (status is 401 or 403 || code is 4012 or 4001)
        {
            throw new InvalidOperationException(
                $"netcup authentication/authorization failed ({status}, {code}): {TrimBody(body)}");
        }
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
            if (string.Equals(apiStatus, "success", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var code = ReadInt(doc.RootElement, "statuscode");
            return code is 2000 or 2001;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static int ReadStatusCode(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return ReadInt(doc.RootElement, "statuscode") ?? 0;
        }
        catch (JsonException)
        {
            return 0;
        }
    }

    private static IEnumerable<JsonElement> EnumerateRecords(JsonElement root)
    {
        if (!root.TryGetProperty("responsedata", out var data))
        {
            yield break;
        }

        if (data.ValueKind == JsonValueKind.Object &&
            data.TryGetProperty("dnsrecords", out var records))
        {
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
    }

    private static bool NamesMatch(string hostname, string relative, string recordName, string zone)
    {
        var normalized = NormalizeHost(hostname);
        if (normalized is "@" or "")
        {
            normalized = "";
        }

        var expectedRelative = relative is "@" or "" ? "" : NormalizeHost(relative);
        return string.Equals(normalized, expectedRelative, StringComparison.Ordinal) ||
               string.Equals(normalized, recordName, StringComparison.Ordinal) ||
               string.Equals(normalized, $"{expectedRelative}.{zone}", StringComparison.Ordinal);
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
