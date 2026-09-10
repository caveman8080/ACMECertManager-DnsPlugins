using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TransIpDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class TransIpDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.transip.nl/v6";
    private const int TxtExpireSeconds = 60;
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public TransIpDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public TransIpDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "transip",
        DisplayName = "TransIP",
        Description = "DNS-01 via the TransIP REST API v6 using an access token or login plus RSA private key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "accessToken",
            Label = "Access Token",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Bearer JWT from the TransIP control panel (optional if login + privateKey)"
        },
        new DnsCredentialField
        {
            Name = "login",
            Label = "Login",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "TransIP account name (required with privateKey)"
        },
        new DnsCredentialField
        {
            Name = "privateKey",
            Label = "Private Key (PEM)",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "RSA private key PEM used to mint a JWT (required with login)"
        },
        new DnsCredentialField
        {
            Name = "globalKey",
            Label = "Global key (token mint)",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default true (token usable from any IP)"
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
        var token = await GetAccessTokenAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        if (await HasTxtAsync(token, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var payload = SerializeDnsEntry(relative, request.TxtValue);
        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/dns",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || IsAlreadyExists(body))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"TransIP add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = await GetAccessTokenAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        if (!await HasTxtAsync(token, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        var payload = SerializeDnsEntry(relative, request.TxtValue);
        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/dns",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 || status is 404 || IsNoMatch(body, status))
        {
            return;
        }

        ThrowIfAuthFailed(status, body);
        throw new InvalidOperationException($"TransIP delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> GetAccessTokenAsync(
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var accessToken = GetOptional(credentials, "accessToken");
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        var login = GetOptional(credentials, "login");
        var privateKey = GetOptional(credentials, "privateKey");
        if (string.IsNullOrWhiteSpace(login) || string.IsNullOrWhiteSpace(privateKey))
        {
            throw new InvalidOperationException(
                "Missing TransIP credentials. Provide accessToken, or login and privateKey.");
        }

        var globalKey = ParseBool(GetOptional(credentials, "globalKey"), defaultValue: true);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var label = "acm" + Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
        var payload = JsonSerializer.Serialize(new AuthRequest
        {
            Login = login,
            Nonce = nonce,
            ReadOnly = false,
            ExpirationTime = "30 minutes",
            Label = label,
            GlobalKey = globalKey
        });

        string signature;
        try
        {
            signature = SignBody(NormalizePem(privateKey), payload);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            throw new InvalidOperationException(
                $"TransIP authentication/authorization failed: invalid private key ({ex.Message})");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/auth");
        request.Headers.TryAddWithoutValidation("Signature", signature);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-TransIpDnsPlugin");
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        ThrowIfAuthFailed(status, body);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException(
                $"TransIP authentication/authorization failed ({status}): {TrimBody(body)}");
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var token = doc.RootElement.TryGetProperty("token", out var tokenElement)
                ? tokenElement.GetString()
                : null;
            if (!string.IsNullOrWhiteSpace(token))
            {
                return token.Trim();
            }
        }
        catch (JsonException)
        {
            // Fall through to the shared error below.
        }

        throw new InvalidOperationException(
            $"TransIP authentication/authorization failed: missing token: {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string token,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(candidate)}/dns",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            ThrowIfAuthFailed(status, body);

            if (status is 404)
            {
                continue;
            }

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"TransIP could not find a DNS zone for '{recordName}'.");
    }

    private async Task<bool> HasTxtAsync(
        string token,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/dns",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        ThrowIfAuthFailed(status, body);
        if (status is 404)
        {
            return false;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"TransIP list DNS entries failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("dnsEntries", out var entries) || entries.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var entry in entries.EnumerateArray())
        {
            var type = ReadString(entry, "type");
            var name = NormalizeHost(ReadString(entry, "name") ?? string.Empty);
            var content = UnquoteTxt(ReadString(entry, "content") ?? string.Empty);
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesMatch(name, relativeName, zone) &&
                string.Equals(content, txtValue, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string token,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-TransIpDnsPlugin");
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
                $"TransIP authentication/authorization failed ({status}): {TrimBody(body)}");
        }
    }

    private static bool IsAlreadyExists(string body) =>
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("already_exists", StringComparison.OrdinalIgnoreCase);

    private static bool IsNoMatch(string body, int status) =>
        status is 406 &&
        (body.Contains("none of the current DNS entries matches", StringComparison.OrdinalIgnoreCase) ||
         body.Contains("no matching", StringComparison.OrdinalIgnoreCase) ||
         body.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
         body.Contains("does not match", StringComparison.OrdinalIgnoreCase));

    private static string SerializeDnsEntry(string relativeName, string txtValue) =>
        JsonSerializer.Serialize(new
        {
            dnsEntry = new
            {
                name = relativeName,
                expire = TxtExpireSeconds,
                type = "TXT",
                content = txtValue
            }
        });

    private static string SignBody(string pem, string body)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    private static string NormalizePem(string value)
    {
        var key = value.Trim();
        if (key.Contains("\\n", StringComparison.Ordinal) && !key.Contains('\n'))
        {
            key = key.Replace("\\n", "\n", StringComparison.Ordinal);
        }

        return key;
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

    private static string? GetOptional(IReadOnlyDictionary<string, string> credentials, string key)
    {
        if (!credentials.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim();
    }

    private static bool ParseBool(string? value, bool defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (bool.TryParse(value, out var parsed))
        {
            return parsed;
        }

        if (value is "1" or "yes")
        {
            return true;
        }

        if (value is "0" or "no")
        {
            return false;
        }

        return defaultValue;
    }

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }

    private sealed class AuthRequest
    {
        [JsonPropertyName("login")]
        public required string Login { get; init; }

        [JsonPropertyName("nonce")]
        public required string Nonce { get; init; }

        [JsonPropertyName("read_only")]
        public required bool ReadOnly { get; init; }

        [JsonPropertyName("expiration_time")]
        public required string ExpirationTime { get; init; }

        [JsonPropertyName("label")]
        public required string Label { get; init; }

        [JsonPropertyName("global_key")]
        public required bool GlobalKey { get; init; }
    }
}
