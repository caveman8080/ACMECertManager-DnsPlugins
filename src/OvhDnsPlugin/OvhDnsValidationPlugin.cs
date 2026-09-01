using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OvhDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class OvhDnsValidationPlugin : IDnsValidationPlugin
{
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "ovh",
        DisplayName = "OVH",
        Description = "DNS-01 via the OVH HTTP API using application key, application secret, and consumer key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "applicationKey",
            Label = "Application Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "OVH application key (OVH_AK)"
        },
        new DnsCredentialField
        {
            Name = "applicationSecret",
            Label = "Application Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "OVH application secret (OVH_AS)"
        },
        new DnsCredentialField
        {
            Name = "consumerKey",
            Label = "Consumer Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "OVH consumer key (OVH_CK)"
        },
        new DnsCredentialField
        {
            Name = "endpoint",
            Label = "API endpoint",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default ovh-eu (ovh-us, ovh-ca, kimsufi-eu, soyoustart-eu, or a full API URL)"
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
        var auth = GetAuth(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(auth, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existingId = await FindRecordIdAsync(auth, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            fieldType = "TXT",
            subDomain = relative,
            target = request.TxtValue,
            ttl = 60
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            auth,
            $"domain/zone/{Uri.EscapeDataString(zone)}/record",
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300 || !body.Contains(request.TxtValue, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"OVH add TXT failed ({status}): {TrimBody(body)}");
        }

        await RefreshZoneAsync(auth, zone, cancellationToken).ConfigureAwait(false);
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var auth = GetAuth(credentials);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(auth, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(auth, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            auth,
            $"domain/zone/{Uri.EscapeDataString(zone)}/record/{Uri.EscapeDataString(recordId)}",
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"OVH delete TXT failed ({status}): {TrimBody(body)}");
        }

        if (status is not 404)
        {
            await RefreshZoneAsync(auth, zone, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task RefreshZoneAsync(Auth auth, string zone, CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Post,
            auth,
            $"domain/zone/{Uri.EscapeDataString(zone)}/refresh",
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"OVH refresh zone failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<string> ResolveZoneAsync(Auth auth, string recordName, CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                auth,
                $"domain/zone/{Uri.EscapeDataString(candidate)}",
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is 404 ||
                body.Contains("This service does not exist", StringComparison.OrdinalIgnoreCase) ||
                body.Contains("This call has not been granted", StringComparison.OrdinalIgnoreCase) ||
                body.Contains("NOT_GRANTED_CALL", StringComparison.OrdinalIgnoreCase))
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

            throw new InvalidOperationException($"OVH get zone failed ({status}): {TrimBody(body)}");
        }

        throw new InvalidOperationException($"OVH could not find a domain zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        Auth auth,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            auth,
            $"domain/zone/{Uri.EscapeDataString(zone)}/record?fieldType=TXT&subDomain={Uri.EscapeDataString(relativeName)}",
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"OVH list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var idElement in doc.RootElement.EnumerateArray())
        {
            var id = idElement.ValueKind switch
            {
                JsonValueKind.Number => idElement.GetRawText(),
                JsonValueKind.String => idElement.GetString(),
                _ => null
            };
            if (string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var (recordStatus, recordBody) = await SendAsync(
                HttpMethod.Get,
                auth,
                $"domain/zone/{Uri.EscapeDataString(zone)}/record/{Uri.EscapeDataString(id)}",
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (recordStatus is < 200 or >= 300)
            {
                continue;
            }

            using var recordDoc = JsonDocument.Parse(recordBody);
            var type = recordDoc.RootElement.TryGetProperty("fieldType", out var typeElement) ? typeElement.GetString() : null;
            var target = recordDoc.RootElement.TryGetProperty("target", out var targetElement) ? targetElement.GetString() : null;
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(UnquoteTxt(target ?? string.Empty), txtValue, StringComparison.Ordinal))
            {
                return id;
            }
        }

        return null;
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        Auth auth,
        string path,
        string? content,
        CancellationToken cancellationToken)
    {
        var url = $"{auth.ApiBase}/{path}";
        var timestamp = await GetTimestampAsync(auth.ApiBase, cancellationToken).ConfigureAwait(false);
        var signature = Sign(auth.ApplicationSecret, auth.ConsumerKey, method.Method, url, content ?? string.Empty, timestamp);

        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("X-Ovh-Application", auth.ApplicationKey);
        request.Headers.TryAddWithoutValidation("X-Ovh-Signature", signature);
        request.Headers.TryAddWithoutValidation("X-Ovh-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-Ovh-Consumer", auth.ConsumerKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-OvhDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (body.Contains("INVALID_CREDENTIAL", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("NOT_CREDENTIAL", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("OVH application key, application secret, or consumer key is not correct.");
        }

        return ((int)response.StatusCode, body);
    }

    private static async Task<string> GetTimestampAsync(string apiBase, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{apiBase}/auth/time");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-OvhDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
        if ((int)response.StatusCode is < 200 or >= 300 || string.IsNullOrWhiteSpace(body))
        {
            throw new InvalidOperationException($"OVH auth time failed ({(int)response.StatusCode}): {TrimBody(body)}");
        }

        return body.Trim('"');
    }

    private static string Sign(
        string applicationSecret,
        string consumerKey,
        string method,
        string url,
        string body,
        string timestamp)
    {
        var payload = $"{applicationSecret}+{consumerKey}+{method}+{url}+{body}+{timestamp}";
        var hash = Convert.ToHexStringLower(SHA1.HashData(Encoding.UTF8.GetBytes(payload)));
        return "$1$" + hash;
    }

    private static Auth GetAuth(IReadOnlyDictionary<string, string> credentials)
    {
        return new Auth(
            GetRequired(credentials, "applicationKey"),
            GetRequired(credentials, "applicationSecret"),
            GetRequired(credentials, "consumerKey"),
            ResolveApiBase(GetOptional(credentials, "endpoint")));
    }

    private static string ResolveApiBase(string? endpoint)
    {
        var value = string.IsNullOrWhiteSpace(endpoint) ? "ovh-eu" : endpoint.Trim();
        if (value.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            return value.TrimEnd('/');
        }

        return value.ToLowerInvariant() switch
        {
            "ovh-eu" or "ovheu" => "https://eu.api.ovh.com/1.0",
            "ovh-us" or "ovhus" => "https://api.us.ovhcloud.com/1.0",
            "ovh-ca" or "ovhca" => "https://ca.api.ovh.com/1.0",
            "kimsufi-eu" or "kimsufieu" => "https://eu.api.kimsufi.com/1.0",
            "kimsufi-ca" or "kimsufica" => "https://ca.api.kimsufi.com/1.0",
            "soyoustart-eu" or "soyoustarteu" => "https://eu.api.soyoustart.com/1.0",
            "soyoustart-ca" or "soyoustartca" => "https://ca.api.soyoustart.com/1.0",
            _ => throw new InvalidOperationException(
                $"Unknown OVH endpoint '{endpoint}'. Use ovh-eu, ovh-us, ovh-ca, kimsufi-eu, kimsufi-ca, soyoustart-eu, soyoustart-ca, or a full API URL.")
        };
    }

    private readonly record struct Auth(
        string ApplicationKey,
        string ApplicationSecret,
        string ConsumerKey,
        string ApiBase);

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
