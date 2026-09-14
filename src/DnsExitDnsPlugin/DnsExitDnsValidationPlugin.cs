using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace DnsExitDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DnsExitDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiUrl = "https://api.dnsexit.com/dns/";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public DnsExitDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public DnsExitDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "dnsexit",
        DisplayName = "DNSExit",
        Description = "DNS-01 via the DNSExit HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "DNSExit API key (DNSEXIT_API_KEY)"
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
        await ZoneOpAsync(apiKey, recordName, request.TxtValue, add: true, cancellationToken).ConfigureAwait(false);
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        await ZoneOpAsync(apiKey, recordName, request.TxtValue, add: false, cancellationToken).ConfigureAwait(false);
    }

    private async Task ZoneOpAsync(
        string apiKey,
        string recordName,
        string txtValue,
        bool add,
        CancellationToken cancellationToken)
    {
        int? authStatus = null;
        string authBody = string.Empty;
        string lastBody = string.Empty;

        foreach (var candidate in CandidateZones(recordName))
        {
            var relative = GetRelativeName(recordName, candidate);
            var payload = add
                ? JsonSerializer.Serialize(new
                {
                    domain = candidate,
                    add = new { type = "TXT", name = relative, content = txtValue, ttl = 1, overwrite = false }
                })
                : JsonSerializer.Serialize(new
                {
                    domain = candidate,
                    delete = new { type = "TXT", name = relative, content = txtValue }
                });

            var (status, body) = await PostAsync(apiKey, payload, cancellationToken).ConfigureAwait(false);
            lastBody = body;

            if (status is 401 or 403 || IsAuthFailure(body))
            {
                authStatus = status;
                authBody = body;
                break;
            }

            if (IsSuccess(status, body) || (add && IsAlreadyExists(body)))
            {
                return;
            }
        }

        if (authStatus is not null)
        {
            throw new InvalidOperationException(
                $"DNSExit authentication/authorization failed ({authStatus}): {TrimBody(authBody)}");
        }

        var action = add ? "add" : "delete";
        throw new InvalidOperationException(
            $"DNSExit {action} TXT failed for '{recordName}': {TrimBody(lastBody)}");
    }

    private async Task<(int Status, string Body)> PostAsync(
        string apiKey,
        string payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUrl);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("apikey", apiKey);
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DnsExitDnsPlugin");
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static bool IsSuccess(int status, string body)
    {
        if (status is < 200 or >= 300)
        {
            return false;
        }

        return ReadCode(body) is 0;
    }

    private static bool IsAlreadyExists(string body) =>
        body.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("duplicate", StringComparison.OrdinalIgnoreCase);

    private static bool IsAuthFailure(string body)
    {
        var code = ReadCode(body);
        if (code is 2 or 3 or 4)
        {
            return true;
        }

        return body.Contains("invalid api", StringComparison.OrdinalIgnoreCase) ||
               body.Contains("api key", StringComparison.OrdinalIgnoreCase) &&
               (body.Contains("invalid", StringComparison.OrdinalIgnoreCase) ||
                body.Contains("unauthorized", StringComparison.OrdinalIgnoreCase));
    }

    private static int? ReadCode(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("code", out var code))
            {
                return null;
            }

            return code.ValueKind switch
            {
                JsonValueKind.Number when code.TryGetInt32(out var n) => n,
                JsonValueKind.String when int.TryParse(code.GetString(), out var n) => n,
                _ => null
            };
        }
        catch (JsonException)
        {
            return null;
        }
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

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }
}
