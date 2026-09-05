using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace SelectelDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class SelectelDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiV1 = "https://api.selectel.ru/domains/v1";
    private const string ApiV2 = "https://api.selectel.ru/domains/v2";
    private const string AuthUrl = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public SelectelDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public SelectelDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "selectel",
        DisplayName = "Selectel",
        Description = "DNS-01 via the Selectel DNS HTTP API (v2 Keystone or legacy v1 API key)."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key (v1)",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Legacy v1 API key (SL_Key); leave blank for v2"
        },
        new DnsCredentialField
        {
            Name = "loginId",
            Label = "Account ID (v2)",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Selectel account ID (SL_Login_ID)"
        },
        new DnsCredentialField
        {
            Name = "projectName",
            Label = "Project Name (v2)",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Selectel project name (SL_Project_Name)"
        },
        new DnsCredentialField
        {
            Name = "loginName",
            Label = "Service User (v2)",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Service user name (SL_Login_Name)"
        },
        new DnsCredentialField
        {
            Name = "password",
            Label = "Service User Password (v2)",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Service user password (SL_Pswd)"
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
        var session = await AuthenticateAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(session, recordName, cancellationToken).ConfigureAwait(false);

        if (session.UseV2)
        {
            await PresentV2Async(session, zone, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await PresentV1Async(session, zone, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var session = await AuthenticateAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(session, recordName, cancellationToken).ConfigureAwait(false);

        if (session.UseV2)
        {
            await CleanupV2Async(session, zone, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await CleanupV1Async(session, zone, recordName, request.TxtValue, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task PresentV2Async(
        Session session,
        Zone zone,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var fqdn = recordName + ".";
        var quoted = QuoteTxt(txtValue);
        var rrset = await FindRrsetAsync(session, zone.Id, fqdn, cancellationToken).ConfigureAwait(false);
        if (rrset is not null &&
            rrset.Contents.Any(value => string.Equals(UnquoteTxt(value), txtValue, StringComparison.Ordinal)))
        {
            return;
        }

        int status;
        string body;
        if (rrset is null)
        {
            var payload = JsonSerializer.Serialize(new
            {
                type = "TXT",
                ttl = 60,
                name = fqdn,
                records = new[] { new { content = quoted } }
            });
            (status, body) = await SendAsync(
                HttpMethod.Post,
                $"{ApiV2}/zones/{Uri.EscapeDataString(zone.Id)}/rrset",
                session,
                payload,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var records = rrset.Contents
                .Select(value => new { content = value })
                .Concat([new { content = quoted }])
                .ToArray();
            var payload = JsonSerializer.Serialize(new { ttl = 60, records });
            (status, body) = await SendAsync(
                HttpMethod.Patch,
                $"{ApiV2}/zones/{Uri.EscapeDataString(zone.Id)}/rrset/{Uri.EscapeDataString(rrset.Id)}",
                session,
                payload,
                cancellationToken).ConfigureAwait(false);
        }

        if (status is >= 200 and < 300 || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Selectel add TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task CleanupV2Async(
        Session session,
        Zone zone,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var fqdn = recordName + ".";
        var rrset = await FindRrsetAsync(session, zone.Id, fqdn, cancellationToken).ConfigureAwait(false);
        if (rrset is null)
        {
            return;
        }

        var remaining = rrset.Contents
            .Where(value => !string.Equals(UnquoteTxt(value), txtValue, StringComparison.Ordinal))
            .ToList();
        if (remaining.Count == rrset.Contents.Count)
        {
            return;
        }

        int status;
        string body;
        if (remaining.Count == 0)
        {
            (status, body) = await SendAsync(
                HttpMethod.Delete,
                $"{ApiV2}/zones/{Uri.EscapeDataString(zone.Id)}/rrset/{Uri.EscapeDataString(rrset.Id)}",
                session,
                content: null,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var payload = JsonSerializer.Serialize(new
            {
                ttl = 60,
                records = remaining.Select(value => new { content = value }).ToArray()
            });
            (status, body) = await SendAsync(
                HttpMethod.Patch,
                $"{ApiV2}/zones/{Uri.EscapeDataString(zone.Id)}/rrset/{Uri.EscapeDataString(rrset.Id)}",
                session,
                payload,
                cancellationToken).ConfigureAwait(false);
        }

        if (status is >= 200 and < 300 || status is 404)
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Selectel delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task PresentV1Async(
        Session session,
        Zone zone,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        if (await FindV1RecordIdAsync(session, zone.Id, recordName, txtValue, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            ttl = 60,
            name = recordName,
            content = txtValue
        });
        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiV1}/{Uri.EscapeDataString(zone.Id)}/records/",
            session,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Selectel add TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task CleanupV1Async(
        Session session,
        Zone zone,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var recordId = await FindV1RecordIdAsync(session, zone.Id, recordName, txtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiV1}/{Uri.EscapeDataString(zone.Id)}/records/{Uri.EscapeDataString(recordId)}",
            session,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || status is 404)
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"Selectel delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<Session> AuthenticateAsync(
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var loginId = GetOptional(credentials, "loginId");
        var projectName = GetOptional(credentials, "projectName");
        var loginName = GetOptional(credentials, "loginName");
        var password = GetOptional(credentials, "password");
        var apiKey = GetOptional(credentials, "apiKey");

        if (!string.IsNullOrWhiteSpace(loginId) &&
            !string.IsNullOrWhiteSpace(projectName) &&
            !string.IsNullOrWhiteSpace(loginName) &&
            !string.IsNullOrWhiteSpace(password))
        {
            var payload = JsonSerializer.Serialize(new
            {
                auth = new
                {
                    identity = new
                    {
                        methods = new[] { "password" },
                        password = new
                        {
                            user = new
                            {
                                name = loginName,
                                domain = new { name = loginId },
                                password
                            }
                        }
                    },
                    scope = new
                    {
                        project = new
                        {
                            name = projectName,
                            domain = new { name = loginId }
                        }
                    }
                }
            });

            using var request = new HttpRequestMessage(HttpMethod.Post, AuthUrl);
            request.Headers.TryAddWithoutValidation("Accept", "application/json");
            request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-SelectelDnsPlugin");
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var status = (int)response.StatusCode;
            if (status is 401 or 403 || status is < 200 or >= 300)
            {
                throw new InvalidOperationException(
                    $"Selectel authentication/authorization failed ({status}): {TrimBody(body)}");
            }

            if (!response.Headers.TryGetValues("X-Subject-Token", out var tokens))
            {
                throw new InvalidOperationException($"Selectel authentication/authorization failed: missing X-Subject-Token: {TrimBody(body)}");
            }

            var token = tokens.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new InvalidOperationException("Selectel authentication/authorization failed: empty X-Subject-Token.");
            }

            return new Session(UseV2: true, Token: token.Trim());
        }

        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            return new Session(UseV2: false, Token: apiKey);
        }

        throw new InvalidOperationException(
            "Missing Selectel credentials. Provide v2 loginId, projectName, loginName, and password, or a v1 apiKey.");
    }

    private async Task<Zone> ResolveZoneAsync(
        Session session,
        string recordName,
        CancellationToken cancellationToken)
    {
        if (session.UseV2)
        {
            var (status, body) = await SendAsync(HttpMethod.Get, $"{ApiV2}/zones", session, content: null, cancellationToken)
                .ConfigureAwait(false);
            ThrowIfAuthFailed(status, body);
            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Selectel list zones failed ({status}): {TrimBody(body)}");
            }

            var zones = ParseV2Zones(body);
            foreach (var candidate in CandidateZones(recordName))
            {
                if (zones.TryGetValue(candidate, out var id))
                {
                    return new Zone(id, candidate);
                }
            }

            throw new InvalidOperationException($"Selectel could not find a DNS zone for '{recordName}'.");
        }

        var (v1Status, v1Body) = await SendAsync(HttpMethod.Get, $"{ApiV1}/", session, content: null, cancellationToken)
            .ConfigureAwait(false);
        ThrowIfAuthFailed(v1Status, v1Body);
        if (v1Status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Selectel list zones failed ({v1Status}): {TrimBody(v1Body)}");
        }

        var v1Zones = ParseV1Zones(v1Body);
        foreach (var candidate in CandidateZones(recordName))
        {
            if (v1Zones.TryGetValue(candidate, out var id))
            {
                return new Zone(id, candidate);
            }
        }

        throw new InvalidOperationException($"Selectel could not find a DNS zone for '{recordName}'.");
    }

    private async Task<Rrset?> FindRrsetAsync(
        Session session,
        string zoneId,
        string fqdn,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiV2}/zones/{Uri.EscapeDataString(zoneId)}/rrset",
            session,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return null;
        }

        ThrowIfAuthFailed(status, body);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Selectel list rrset failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        foreach (var item in EnumerateResult(doc.RootElement))
        {
            var type = ReadString(item, "type");
            var name = NormalizeHost(ReadString(item, "name") ?? string.Empty);
            var id = ReadString(item, "id");
            if (!string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(name, NormalizeHost(fqdn), StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var contents = new List<string>();
            if (item.TryGetProperty("records", out var records) && records.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in records.EnumerateArray())
                {
                    var content = ReadString(record, "content");
                    if (!string.IsNullOrWhiteSpace(content))
                    {
                        contents.Add(content);
                    }
                }
            }

            return new Rrset(id, contents);
        }

        return null;
    }

    private async Task<string?> FindV1RecordIdAsync(
        Session session,
        string zoneId,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiV1}/{Uri.EscapeDataString(zoneId)}/records/",
            session,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404)
        {
            return null;
        }

        ThrowIfAuthFailed(status, body);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Selectel list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        IEnumerable<JsonElement> records = doc.RootElement.ValueKind == JsonValueKind.Array
            ? doc.RootElement.EnumerateArray()
            : doc.RootElement.TryGetProperty("records", out var wrapped) && wrapped.ValueKind == JsonValueKind.Array
                ? wrapped.EnumerateArray()
                : [];

        foreach (var record in records)
        {
            var type = ReadString(record, "type");
            var name = NormalizeHost(ReadString(record, "name") ?? string.Empty);
            var content = UnquoteTxt(ReadString(record, "content") ?? string.Empty);
            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(name, recordName, StringComparison.Ordinal) &&
                string.Equals(content, txtValue, StringComparison.Ordinal) &&
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
        Session session,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation(session.UseV2 ? "X-Auth-Token" : "X-Token", session.Token);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-SelectelDnsPlugin");
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
        if (status is 401 or 403)
        {
            throw new InvalidOperationException(
                $"Selectel authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsAlreadyExists(string body) =>
        body.Contains("already_exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase);

    private static Dictionary<string, string> ParseV2Zones(string body)
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(body);
        foreach (var zone in EnumerateResult(doc.RootElement))
        {
            var name = ReadString(zone, "name");
            var id = ReadString(zone, "id");
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(id))
            {
                names[NormalizeHost(name)] = id;
            }
        }

        return names;
    }

    private static Dictionary<string, string> ParseV1Zones(string body)
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(body);
        IEnumerable<JsonElement> zones = doc.RootElement.ValueKind == JsonValueKind.Array
            ? doc.RootElement.EnumerateArray()
            : EnumerateResult(doc.RootElement);

        foreach (var zone in zones)
        {
            var name = ReadString(zone, "name");
            var id = ReadId(zone, "id");
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(id))
            {
                names[NormalizeHost(name)] = id;
            }
        }

        return names;
    }

    private static IEnumerable<JsonElement> EnumerateResult(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
            {
                yield return item;
            }

            yield break;
        }

        if (root.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in result.EnumerateArray())
            {
                yield return item;
            }
        }
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

    private sealed record Session(bool UseV2, string Token);

    private sealed record Zone(string Id, string Name);

    private sealed record Rrset(string Id, List<string> Contents);
}
