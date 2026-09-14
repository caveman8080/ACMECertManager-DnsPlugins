using ACMECertManager;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace StratoDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class StratoDnsValidationPlugin : IDnsValidationPlugin
{
    private const string DefaultPortalUrl = "https://www.strato.de/apps/CustomerService";
    private static readonly HttpClient SharedHttpClient = CreateSessionClient();

    private readonly HttpClient _httpClient;

    public StratoDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public StratoDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "strato",
        DisplayName = "Strato",
        Description = "DNS-01 via the Strato CustomerService portal (no public DNS REST API)."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "username",
            Label = "Customer number or username",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "STRATO customer number or login"
        },
        new DnsCredentialField
        {
            Name = "password",
            Label = "Password",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "STRATO customer password"
        },
        new DnsCredentialField
        {
            Name = "portalUrl",
            Label = "Portal URL",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default https://www.strato.de/apps/CustomerService"
        },
        new DnsCredentialField
        {
            Name = "totpSecret",
            Label = "TOTP secret",
            IsRequired = false,
            IsSecret = true,
            Placeholder = "Optional, for two-factor login"
        },
        new DnsCredentialField
        {
            Name = "totpDeviceName",
            Label = "TOTP device name",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, 2FA device name shown in the portal"
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

    public Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken) =>
        MutateTxtAsync(request, credentials, add: true, cancellationToken);

    public Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken) =>
        MutateTxtAsync(request, credentials, add: false, cancellationToken);

    private async Task MutateTxtAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        bool add,
        CancellationToken cancellationToken)
    {
        var username = GetRequired(credentials, "username");
        var password = GetRequired(credentials, "password");
        var portalUrl = GetOptional(credentials, "portalUrl");
        if (string.IsNullOrWhiteSpace(portalUrl))
        {
            portalUrl = DefaultPortalUrl;
        }

        var totpSecret = GetOptional(credentials, "totpSecret");
        var totpDeviceName = GetOptional(credentials, "totpDeviceName");
        var recordName = NormalizeHost(request.RecordName);

        var sessionId = await LoginAsync(portalUrl, username, password, totpSecret, totpDeviceName, cancellationToken)
            .ConfigureAwait(false);
        var (packageId, zone) = await GetPackageAsync(portalUrl, sessionId, recordName, cancellationToken)
            .ConfigureAwait(false);
        var prefix = GetRelativeName(recordName, zone);
        var records = await GetTxtRecordsAsync(portalUrl, sessionId, packageId, zone, cancellationToken)
            .ConfigureAwait(false);

        var changed = false;
        if (add)
        {
            if (!records.Any(r =>
                    r.Type.Equals("TXT", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(NormalizeHost(r.Prefix), NormalizeHost(prefix), StringComparison.Ordinal) &&
                    string.Equals(r.Value, request.TxtValue, StringComparison.Ordinal)))
            {
                records.Add(new DnsRecord(prefix, "TXT", request.TxtValue));
                changed = true;
            }
        }
        else
        {
            var remaining = records
                .Where(r =>
                    !(r.Type.Equals("TXT", StringComparison.OrdinalIgnoreCase) &&
                      string.Equals(NormalizeHost(r.Prefix), NormalizeHost(prefix), StringComparison.Ordinal) &&
                      string.Equals(r.Value, request.TxtValue, StringComparison.Ordinal)))
                .ToList();
            if (remaining.Count != records.Count)
            {
                records = remaining;
                changed = true;
            }
        }

        if (!changed)
        {
            return;
        }

        await PushTxtRecordsAsync(portalUrl, sessionId, packageId, zone, records, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<string> LoginAsync(
        string portalUrl,
        string username,
        string password,
        string totpSecret,
        string totpDeviceName,
        CancellationToken cancellationToken)
    {
        _ = await SendAsync(HttpMethod.Get, portalUrl, content: null, cancellationToken).ConfigureAwait(false);

        var login = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["identifier"] = username,
            ["passwd"] = password,
            ["action_customer_login.x"] = "Login"
        });
        var (status, body, finalUrl, location) = await SendAsync(
            HttpMethod.Post,
            portalUrl,
            login,
            cancellationToken).ConfigureAwait(false);

        var sessionId = ExtractSessionId(finalUrl, location, body);
        if (string.IsNullOrWhiteSpace(sessionId) && IsTwoFactor(body))
        {
            if (string.IsNullOrWhiteSpace(totpSecret) || string.IsNullOrWhiteSpace(totpDeviceName))
            {
                throw new InvalidOperationException(
                    "Strato login requires two-factor authentication. Set totpSecret and totpDeviceName.");
            }

            var totpFields = BuildTotpFields(body, username, totpSecret, totpDeviceName);
            var totpContent = new FormUrlEncodedContent(totpFields);
            (status, body, finalUrl, location) = await SendAsync(
                HttpMethod.Post,
                portalUrl,
                totpContent,
                cancellationToken).ConfigureAwait(false);
            sessionId = ExtractSessionId(finalUrl, location, body);
        }

        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw new InvalidOperationException(
                $"Strato authentication/authorization failed ({status}): login did not return a sessionID.");
        }

        return sessionId;
    }

    private async Task<(string PackageId, string Zone)> GetPackageAsync(
        string portalUrl,
        string sessionId,
        string recordName,
        CancellationToken cancellationToken)
    {
        var url = AppendQuery(portalUrl, new Dictionary<string, string>
        {
            ["sessionID"] = sessionId,
            ["cID"] = "0",
            ["node"] = "kds_CustomerEntryPage"
        });
        var (_, body, _, _) = await SendAsync(HttpMethod.Get, url, content: null, cancellationToken)
            .ConfigureAwait(false);

        var zone = GuessZone(recordName);
        foreach (var candidate in CandidateZones(recordName))
        {
            if (candidate.StartsWith("_acme-challenge.", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (body.Contains(candidate, StringComparison.OrdinalIgnoreCase))
            {
                zone = candidate;
                break;
            }
        }

        var escaped = Regex.Escape(zone);
        var match = Regex.Match(
            body,
            $@"cID=(\d+)[\s\S]{{0,500}}{escaped}|{escaped}[\s\S]{{0,500}}cID=(\d+)",
            RegexOptions.IgnoreCase);
        var packageId = match.Success
            ? (match.Groups[1].Success && match.Groups[1].Length > 0
                ? match.Groups[1].Value
                : match.Groups[2].Value)
            : "1";
        return (packageId, zone);
    }

    private async Task<List<DnsRecord>> GetTxtRecordsAsync(
        string portalUrl,
        string sessionId,
        string packageId,
        string zone,
        CancellationToken cancellationToken)
    {
        var url = AppendQuery(portalUrl, new Dictionary<string, string>
        {
            ["sessionID"] = sessionId,
            ["cID"] = packageId,
            ["node"] = "ManageDomains",
            ["action_show_txt_records"] = "",
            ["vhost"] = zone
        });
        var (_, body, _, _) = await SendAsync(HttpMethod.Get, url, content: null, cancellationToken)
            .ConfigureAwait(false);
        return ParseRecords(body);
    }

    private async Task PushTxtRecordsAsync(
        string portalUrl,
        string sessionId,
        string packageId,
        string zone,
        List<DnsRecord> records,
        CancellationToken cancellationToken)
    {
        var pairs = new List<KeyValuePair<string, string>>
        {
            new("sessionID", sessionId),
            new("cID", packageId),
            new("node", "ManageDomains"),
            new("vhost", zone),
            new("spf_type", "NONE")
        };
        foreach (var record in records)
        {
            pairs.Add(new("prefix", record.Prefix));
            pairs.Add(new("type", record.Type));
            pairs.Add(new("value", record.Value));
        }

        pairs.Add(new("action_change_txt_records", "Einstellung übernehmen"));

        var (status, body, _, _) = await SendAsync(
            HttpMethod.Post,
            portalUrl,
            new FormUrlEncodedContent(pairs),
            cancellationToken).ConfigureAwait(false);
        if (status is < 200 or >= 400)
        {
            throw new InvalidOperationException($"Strato update TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private async Task<(int Status, string Body, string FinalUrl, string Location)> SendAsync(
        HttpMethod method,
        string url,
        HttpContent? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation(
            "User-Agent",
            "Mozilla/5.0 ACMECertManager-StratoDnsPlugin");
        request.Headers.TryAddWithoutValidation("Accept", "text/html,application/xhtml+xml");
        if (content is not null)
        {
            request.Content = content;
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var finalUrl = response.RequestMessage?.RequestUri?.ToString() ?? url;
        var location = response.Headers.Location?.ToString() ?? string.Empty;
        return ((int)response.StatusCode, body, finalUrl, location);
    }

    internal static List<DnsRecord> ParseRecords(string html)
    {
        var records = new List<DnsRecord>();
        var parts = Regex.Split(html, @"txt-record-tmpl", RegexOptions.IgnoreCase);
        for (var i = 1; i < parts.Length; i++)
        {
            var block = parts[i];
            var prefix = MatchNamedValue(block, "prefix");
            var type = MatchSelectedType(block);
            var value = MatchTextarea(block, "value");
            if (string.IsNullOrWhiteSpace(type))
            {
                continue;
            }

            records.Add(new DnsRecord(prefix, type, value));
        }

        return records;
    }

    internal static string GenerateTotp(string secret)
    {
        var key = Base32Decode(secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30L;
        var bytes = BitConverter.GetBytes(timestep);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(bytes);
        var offset = hash[^1] & 0x0F;
        var binary =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);
        return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    private static Dictionary<string, string> BuildTotpFields(
        string html,
        string username,
        string totpSecret,
        string totpDeviceName)
    {
        var fields = new Dictionary<string, string>
        {
            ["identifier"] = username,
            ["action_customer_login.x"] = "1",
            ["totp"] = GenerateTotp(totpSecret)
        };

        var totpToken = Regex.Match(
            html,
            @"name=[""']totp_token[""'][^>]*value=[""']([^""']*)[""']",
            RegexOptions.IgnoreCase);
        if (!totpToken.Success)
        {
            totpToken = Regex.Match(
                html,
                @"value=[""']([^""']*)[""'][^>]*name=[""']totp_token[""']",
                RegexOptions.IgnoreCase);
        }

        if (totpToken.Success)
        {
            fields["totp_token"] = totpToken.Groups[1].Value;
        }

        var device = Regex.Match(
            html,
            $@"<option[^>]*value=[""']([^""']*{Regex.Escape(username)}[^""']*)[""'][^>]*>([^<]*)",
            RegexOptions.IgnoreCase);
        var found = false;
        foreach (Match match in Regex.Matches(
                     html,
                     @"<option[^>]*value=[""']([^""']+)[""'][^>]*>([^<]*)",
                     RegexOptions.IgnoreCase))
        {
            if (string.Equals(match.Groups[2].Value.Trim(), totpDeviceName.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                fields["pw_id"] = match.Groups[1].Value;
                found = true;
                break;
            }
        }

        if (!found && device.Success)
        {
            fields["pw_id"] = device.Groups[1].Value;
        }

        return fields;
    }

    private static bool IsTwoFactor(string html) =>
        html.Contains("Zwei-Faktor", StringComparison.OrdinalIgnoreCase) ||
        html.Contains("Two-factor", StringComparison.OrdinalIgnoreCase) ||
        html.Contains("name=\"totp\"", StringComparison.OrdinalIgnoreCase) ||
        html.Contains("name='totp'", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractSessionId(string finalUrl, string location, string body)
    {
        foreach (var candidate in new[] { finalUrl, location, body })
        {
            if (string.IsNullOrEmpty(candidate))
            {
                continue;
            }

            var match = Regex.Match(candidate, @"sessionID=([^&\s""']+)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return Uri.UnescapeDataString(match.Groups[1].Value);
            }
        }

        return null;
    }

    private static string MatchNamedValue(string block, string name)
    {
        var match = Regex.Match(
            block,
            $@"name=[""']{name}[""'][^>]*value=[""']([^""']*)[""']",
            RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            match = Regex.Match(
                block,
                $@"value=[""']([^""']*)[""'][^>]*name=[""']{name}[""']",
                RegexOptions.IgnoreCase);
        }

        return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value) : string.Empty;
    }

    private static string MatchTextarea(string block, string name)
    {
        var match = Regex.Match(
            block,
            $@"<textarea[^>]*name=[""']{name}[""'][^>]*>([\s\S]*?)</textarea>",
            RegexOptions.IgnoreCase);
        return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value).Trim() : string.Empty;
    }

    private static string MatchSelectedType(string block)
    {
        var selected = Regex.Match(block, @"<option[^>]*selected[^>]*>([^<]+)", RegexOptions.IgnoreCase);
        if (selected.Success)
        {
            return selected.Groups[1].Value.Trim();
        }

        var valued = Regex.Match(
            block,
            @"<select[^>]*name=[""']type[""'][^>]*value=[""']([^""']+)[""']",
            RegexOptions.IgnoreCase);
        if (valued.Success)
        {
            return valued.Groups[1].Value.Trim();
        }

        var optionVal = Regex.Match(
            block,
            @"<option[^>]*value=[""'](TXT|CNAME)[""']",
            RegexOptions.IgnoreCase);
        if (optionVal.Success)
        {
            return optionVal.Groups[1].Value.Trim();
        }

        return "TXT";
    }

    private static string AppendQuery(string url, Dictionary<string, string> query)
    {
        var builder = new UriBuilder(url);
        var existing = string.IsNullOrEmpty(builder.Query) ? string.Empty : builder.Query.TrimStart('?');
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(existing))
        {
            parts.Add(existing);
        }

        foreach (var pair in query)
        {
            parts.Add($"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}");
        }

        builder.Query = string.Join("&", parts);
        return builder.Uri.ToString();
    }

    private static HttpClient CreateSessionClient()
    {
        var handler = new HttpClientHandler
        {
            CookieContainer = new CookieContainer(),
            UseCookies = true,
            AllowAutoRedirect = true
        };
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    private static byte[] Base32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var cleaned = input.Trim().Replace(" ", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal)
            .TrimEnd('=').ToUpperInvariant();
        var bits = 0;
        var value = 0;
        var output = new List<byte>(cleaned.Length);
        foreach (var ch in cleaned)
        {
            var index = alphabet.IndexOf(ch);
            if (index < 0)
            {
                throw new InvalidOperationException("Strato totpSecret is not valid Base32.");
            }

            value = (value << 5) | index;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)((value >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return output.ToArray();
    }

    private static IEnumerable<string> CandidateZones(string fqdn)
    {
        var labels = NormalizeHost(fqdn).Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < labels.Length - 1; i++)
        {
            yield return string.Join('.', labels.Skip(i));
        }
    }

    private static string GuessZone(string recordName)
    {
        var labels = NormalizeHost(recordName).Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 2)
        {
            throw new InvalidOperationException($"Strato could not derive a zone from '{recordName}'.");
        }

        return string.Join('.', labels.TakeLast(2));
    }

    private static string GetRelativeName(string fqdn, string zone)
    {
        fqdn = NormalizeHost(fqdn);
        zone = NormalizeHost(zone);
        if (fqdn == zone)
        {
            return string.Empty;
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

    private static string GetOptional(IReadOnlyDictionary<string, string> credentials, string key) =>
        credentials.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : string.Empty;

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }

    internal readonly record struct DnsRecord(string Prefix, string Type, string Value);
}
