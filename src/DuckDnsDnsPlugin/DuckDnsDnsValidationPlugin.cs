using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace DuckDnsDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DuckDnsDnsValidationPlugin : IDnsValidationPlugin
{
    private const string UpdateUrl = "https://www.duckdns.org/update";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "duckdns",
        DisplayName = "DuckDNS",
        Description = "DNS-01 via the DuckDNS HTTP update API using an account token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "token",
            Label = "Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "DuckDNS account token"
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
        var token = GetRequired(credentials, "token");
        var domain = ExtractDuckDnsDomain(request.RecordName);
        var url =
            $"{UpdateUrl}?domains={Uri.EscapeDataString(domain)}&token={Uri.EscapeDataString(token)}&txt={Uri.EscapeDataString(request.TxtValue)}";

        var response = await GetUpdateAsync(url, cancellationToken).ConfigureAwait(false);
        if (!IsOk(response))
        {
            throw new InvalidOperationException($"DuckDNS TXT update failed. Response: {response}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "token");
        var domain = ExtractDuckDnsDomain(request.RecordName);
        // DuckDNS has a single TXT slot per domain; clear=true removes it (acme.sh dns_duckdns_rm).
        var url =
            $"{UpdateUrl}?domains={Uri.EscapeDataString(domain)}&token={Uri.EscapeDataString(token)}&txt=&clear=true";

        var response = await GetUpdateAsync(url, cancellationToken).ConfigureAwait(false);
        if (!IsOk(response))
        {
            throw new InvalidOperationException($"DuckDNS TXT clear failed. Response: {response}");
        }
    }

    private static async Task<string> GetUpdateAsync(string url, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DuckDnsDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"DuckDNS request failed with {(int)response.StatusCode}: {response.ReasonPhrase}");
        }

        return payload.Trim();
    }

    private static string ExtractDuckDnsDomain(string recordName)
    {
        var host = recordName.Trim().TrimEnd('.').ToLowerInvariant();
        var match = Regex.Match(host, @"^(?:_acme-challenge\.)?(?:[a-z0-9-]+\.)*([a-z0-9-]+)\.duckdns\.org$");
        if (!match.Success)
        {
            throw new InvalidOperationException(
                $"DuckDNS record name must be a *.duckdns.org name (got '{recordName}').");
        }

        return match.Groups[1].Value;
    }

    private static bool IsOk(string response)
    {
        return response.Equals("OK", StringComparison.OrdinalIgnoreCase) ||
               (response.Contains("OK", StringComparison.OrdinalIgnoreCase) &&
                response.Contains("UPDATED", StringComparison.OrdinalIgnoreCase));
    }

    private static string GetRequired(IReadOnlyDictionary<string, string> credentials, string key)
    {
        if (!credentials.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Missing required credential '{key}'.");
        }

        return value.Trim();
    }
}
