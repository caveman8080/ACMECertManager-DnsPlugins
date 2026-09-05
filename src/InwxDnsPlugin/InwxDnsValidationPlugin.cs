using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace InwxDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class InwxDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiUrl = "https://api.domrobot.com/jsonrpc/";
    private static readonly HttpClient SharedHttpClient = new(new HttpClientHandler { UseCookies = false })
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public InwxDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public InwxDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "inwx",
        DisplayName = "INWX",
        Description = "DNS-01 via the INWX DomRobot JSON-RPC HTTP API using username and password."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "username",
            Label = "Username",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "INWX username (INWX_User)"
        },
        new DnsCredentialField
        {
            Name = "password",
            Label = "Password",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "INWX password (INWX_Password)"
        },
        new DnsCredentialField
        {
            Name = "sharedSecret",
            Label = "Shared Secret (optional 2FA)",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Optional TOTP secret (INWX_Shared_Secret)"
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
        var cookie = await LoginAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(cookie, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        if (await FindRecordIdAsync(cookie, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        var (status, body, code) = await CallAsync(
            "nameserver.createRecord",
            new Dictionary<string, object?>
            {
                ["domain"] = zone,
                ["type"] = "TXT",
                ["content"] = request.TxtValue,
                ["name"] = relative,
                ["ttl"] = 300
            },
            cookie,
            cancellationToken).ConfigureAwait(false);

        if (IsRpcSuccess(status, code) || IsAlreadyExists(body, code))
        {
            return;
        }

        ThrowIfAuthFailed(status, body, code);
        throw new InvalidOperationException($"INWX add TXT failed ({status}, {code}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var cookie = await LoginAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(cookie, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(cookie, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body, code) = await CallAsync(
            "nameserver.deleteRecord",
            new Dictionary<string, object?> { ["id"] = recordId },
            cookie,
            cancellationToken).ConfigureAwait(false);

        if (IsRpcSuccess(status, code) || status is 404 || code is 2303 or 2308)
        {
            return;
        }

        ThrowIfAuthFailed(status, body, code);
        throw new InvalidOperationException($"INWX delete TXT failed ({status}, {code}): {TrimBody(body)}");
    }

    private async Task<string?> LoginAsync(
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var username = GetRequired(credentials, "username");
        var password = GetRequired(credentials, "password");
        var sharedSecret = GetOptional(credentials, "sharedSecret");

        var (status, body, code, cookie) = await CallWithCookieAsync(
            "account.login",
            new Dictionary<string, object?>
            {
                ["user"] = username,
                ["pass"] = password
            },
            cookie: null,
            cancellationToken).ConfigureAwait(false);

        if (!IsRpcSuccess(status, code))
        {
            throw new InvalidOperationException(
                $"INWX authentication/authorization failed ({status}, {code}): {TrimBody(body)}");
        }

        if (NeedsTotp(body))
        {
            if (string.IsNullOrWhiteSpace(sharedSecret))
            {
                throw new InvalidOperationException(
                    "INWX authentication/authorization failed: Mobile TAN required; set sharedSecret.");
            }

            var tan = GenerateTotp(sharedSecret);
            var (unlockStatus, unlockBody, unlockCode, unlockCookie) = await CallWithCookieAsync(
                "account.unlock",
                new Dictionary<string, object?> { ["tan"] = tan },
                cookie,
                cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(unlockCookie))
            {
                cookie = MergeCookies(cookie, unlockCookie);
            }

            if (!IsRpcSuccess(unlockStatus, unlockCode))
            {
                throw new InvalidOperationException(
                    $"INWX authentication/authorization failed ({unlockStatus}, {unlockCode}): {TrimBody(unlockBody)}");
            }
        }

        return cookie;
    }

    private async Task<string> ResolveZoneAsync(
        string? cookie,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body, code) = await CallAsync(
            "nameserver.list",
            new Dictionary<string, object?> { ["pagelimit"] = 9999 },
            cookie,
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body, code);
        if (!IsRpcSuccess(status, code))
        {
            throw new InvalidOperationException($"INWX list zones failed ({status}, {code}): {TrimBody(body)}");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        using (var doc = JsonDocument.Parse(body))
        {
            foreach (var domain in EnumerateNamed(doc.RootElement, "domain", "name"))
            {
                names.Add(NormalizeHost(domain));
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            if (names.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"INWX could not find a DNS zone for '{recordName}'.");
    }

    private async Task<string?> FindRecordIdAsync(
        string? cookie,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body, code) = await CallAsync(
            "nameserver.info",
            new Dictionary<string, object?>
            {
                ["domain"] = zone,
                ["type"] = "TXT",
                ["name"] = relativeName,
                ["content"] = txtValue
            },
            cookie,
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body, code);
        if (code is 2303 or 2308)
        {
            return null;
        }

        if (!IsRpcSuccess(status, code))
        {
            throw new InvalidOperationException($"INWX list records failed ({status}, {code}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        foreach (var record in EnumerateRecords(doc.RootElement))
        {
            var type = ReadString(record, "type");
            var name = ReadString(record, "name") ?? string.Empty;
            var content = UnquoteTxt(ReadString(record, "content") ?? string.Empty);
            var id = ReadId(record, "id");
            var normalizedName = NormalizeHost(name);
            if (normalizedName == "@")
            {
                normalizedName = "";
            }

            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                (string.Equals(normalizedName, relativeName, StringComparison.Ordinal) ||
                 string.Equals(normalizedName, $"{relativeName}.{zone}", StringComparison.Ordinal) ||
                 (relativeName.Length == 0 && (normalizedName.Length == 0 || string.Equals(normalizedName, zone, StringComparison.Ordinal)))) &&
                string.Equals(content, txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private async Task<(int Status, string Body, int Code)> CallAsync(
        string method,
        Dictionary<string, object?> parameters,
        string? cookie,
        CancellationToken cancellationToken)
    {
        var (status, body, code, _) = await CallWithCookieAsync(method, parameters, cookie, cancellationToken)
            .ConfigureAwait(false);
        return (status, body, code);
    }

    private async Task<(int Status, string Body, int Code, string? Cookie)> CallWithCookieAsync(
        string method,
        Dictionary<string, object?> parameters,
        string? cookie,
        CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["method"] = method,
            ["params"] = parameters
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUrl);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-InwxDnsPlugin");
        if (!string.IsNullOrWhiteSpace(cookie))
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }

        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var setCookie = ExtractCookie(response);
        return ((int)response.StatusCode, body, ReadRpcCode(body), MergeCookies(cookie, setCookie));
    }

    private static void ThrowIfAuthFailed(int status, string body, int code)
    {
        if (status is 401 or 403 || code is 2200 or 2201)
        {
            throw new InvalidOperationException(
                $"INWX authentication/authorization failed ({status}, {code}): {TrimBody(body)}");
        }
    }

    private static bool IsRpcSuccess(int status, int code) =>
        status is >= 200 and < 300 && code is >= 1000 and < 2000;

    private static bool IsAlreadyExists(string body, int code) =>
        code is 2302 ||
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("Object exists", StringComparison.OrdinalIgnoreCase);

    private static bool NeedsTotp(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("resData", out var data) &&
                data.ValueKind == JsonValueKind.Object)
            {
                var tfa = ReadString(data, "tfa");
                return string.Equals(tfa, "GOOGLE-AUTH", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch (JsonException)
        {
            // Fall through.
        }

        return body.Contains("GOOGLE-AUTH", StringComparison.OrdinalIgnoreCase);
    }

    private static int ReadRpcCode(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return ReadInt(doc.RootElement, "code") ?? 0;
        }
        catch (JsonException)
        {
            return 0;
        }
    }

    private static IEnumerable<JsonElement> EnumerateRecords(JsonElement root)
    {
        if (!root.TryGetProperty("resData", out var data))
        {
            yield break;
        }

        if (data.TryGetProperty("record", out var record))
        {
            if (record.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in record.EnumerateArray())
                {
                    yield return item;
                }
            }
            else if (record.ValueKind == JsonValueKind.Object)
            {
                yield return record;
            }
        }
    }

    private static IEnumerable<string> EnumerateNamed(JsonElement root, params string[] names)
    {
        var stack = new Stack<JsonElement>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            switch (current.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var name in names)
                    {
                        var value = ReadString(current, name);
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            yield return value;
                        }
                    }

                    foreach (var property in current.EnumerateObject())
                    {
                        if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                        {
                            stack.Push(property.Value);
                        }
                    }

                    break;
                case JsonValueKind.Array:
                    foreach (var item in current.EnumerateArray())
                    {
                        stack.Push(item);
                    }

                    break;
            }
        }
    }

    private static string? ExtractCookie(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            return null;
        }

        var parts = new List<string>();
        foreach (var header in cookies)
        {
            var pair = header.Split(';', 2)[0].Trim();
            if (!string.IsNullOrWhiteSpace(pair) && pair.Contains('='))
            {
                parts.Add(pair);
            }
        }

        return parts.Count == 0 ? null : string.Join("; ", parts);
    }

    private static string? MergeCookies(string? existing, string? extra)
    {
        if (string.IsNullOrWhiteSpace(existing))
        {
            return extra;
        }

        if (string.IsNullOrWhiteSpace(extra))
        {
            return existing;
        }

        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in new[] { existing, extra })
        {
            foreach (var part in source.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var idx = part.IndexOf('=');
                if (idx <= 0)
                {
                    continue;
                }

                map[part[..idx]] = part[(idx + 1)..];
            }
        }

        return string.Join("; ", map.Select(pair => $"{pair.Key}={pair.Value}"));
    }

    private static string GenerateTotp(string base32Secret)
    {
        var key = DecodeBase32(base32Secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var message = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(message);
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(message);
        var offset = hash[^1] & 0x0F;
        var binary =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);
        return (binary % 1_000_000).ToString("D6");
    }

    private static byte[] DecodeBase32(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var cleaned = new string(input.Trim().TrimEnd('=').ToUpperInvariant().Where(c => c is not ' ' and not '-').ToArray());
        var bits = 0;
        var value = 0;
        var bytes = new List<byte>(cleaned.Length * 5 / 8);
        foreach (var ch in cleaned)
        {
            var idx = alphabet.IndexOf(ch);
            if (idx < 0)
            {
                throw new InvalidOperationException("INWX sharedSecret is not valid base32.");
            }

            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return [.. bytes];
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
