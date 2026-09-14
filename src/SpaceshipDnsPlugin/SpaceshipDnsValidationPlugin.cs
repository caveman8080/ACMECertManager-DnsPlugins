using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace SpaceshipDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class SpaceshipDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://spaceship.dev/api/v1";
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    private readonly HttpClient _httpClient;

    public SpaceshipDnsValidationPlugin()
        : this(SharedHttpClient)
    {
    }

    public SpaceshipDnsValidationPlugin(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
    }

    public DnsPluginMetadata Metadata => new()
    {
        Id = "spaceship",
        DisplayName = "Spaceship",
        Description = "DNS-01 via the Spaceship HTTP API using an API key and API secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Spaceship API key (SPACESHIP_API_KEY)"
        },
        new DnsCredentialField
        {
            Name = "apiSecret",
            Label = "API Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Spaceship API secret (SPACESHIP_API_SECRET)"
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
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var payload = JsonSerializer.Serialize(new
        {
            force = true,
            items = new[]
            {
                new
                {
                    type = "TXT",
                    name = relative,
                    value = request.TxtValue,
                    ttl = 600
                }
            }
        });

        var (status, body) = await SendAsync(
            HttpMethod.Put,
            apiKey,
            apiSecret,
            $"dns/records/{Uri.EscapeDataString(zone)}",
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300)
        {
            return;
        }

        throw new InvalidOperationException($"Spaceship add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var payload = JsonSerializer.Serialize(new[]
        {
            new
            {
                type = "TXT",
                name = relative,
                value = request.TxtValue
            }
        });

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            apiKey,
            apiSecret,
            $"dns/records/{Uri.EscapeDataString(zone)}",
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 or 404)
        {
            return;
        }

        throw new InvalidOperationException($"Spaceship delete TXT failed ({status}): {TrimBody(body)}");
    }

    private async Task<string> ResolveZoneAsync(
        string apiKey,
        string apiSecret,
        string recordName,
        CancellationToken cancellationToken)
    {
        int? authStatus = null;
        string authBody = string.Empty;

        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                apiKey,
                apiSecret,
                $"dns/records/{Uri.EscapeDataString(candidate)}?take=1&skip=0",
                payload: null,
                cancellationToken).ConfigureAwait(false);

            if (status is 401 or 403)
            {
                authStatus = status;
                authBody = body;
                break;
            }

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        if (authStatus is not null)
        {
            throw new InvalidOperationException(
                $"Spaceship authentication/authorization failed ({authStatus}): {TrimBody(authBody)}");
        }

        throw new InvalidOperationException($"Spaceship could not find a zone for '{recordName}'.");
    }

    private async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string apiKey,
        string apiSecret,
        string endpoint,
        string? payload,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, $"{ApiBase}/{endpoint}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("X-API-Key", apiKey);
        request.Headers.TryAddWithoutValidation("X-API-Secret", apiSecret);
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-SpaceshipDnsPlugin");
        if (payload is not null)
        {
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
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
