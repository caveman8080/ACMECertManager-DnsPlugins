using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace PorkbunDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class PorkbunDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.porkbun.com/api/json/v3";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "porkbun",
        DisplayName = "Porkbun",
        Description = "DNS-01 via the Porkbun HTTP API using an API key and secret API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Porkbun API key"
        },
        new DnsCredentialField
        {
            Name = "apiSecret",
            Label = "Secret API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Porkbun secret API key"
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

        var body = new Dictionary<string, object>
        {
            ["apikey"] = apiKey,
            ["secretapikey"] = apiSecret,
            ["name"] = relative,
            ["type"] = "TXT",
            ["content"] = request.TxtValue,
            ["ttl"] = "120"
        };

        var (status, response) = await PostAsync($"dns/create/{zone}", body, cancellationToken).ConfigureAwait(false);
        if (IsSuccess(response) || response.Contains("already exists", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException($"Porkbun add TXT failed ({status}): {TrimBody(response)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var apiSecret = GetRequired(credentials, "apiSecret");
        var recordName = NormalizeHost(request.RecordName);
        var (zone, retrieveBody) = await RetrieveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);

        using var doc = JsonDocument.Parse(retrieveBody);
        if (!doc.RootElement.TryGetProperty("records", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            var content = record.TryGetProperty("content", out var contentElement) ? contentElement.GetString() : null;
            var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var id = record.TryGetProperty("id", out var idElement) ? idElement.ToString() : null;
            if (!string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(content, request.TxtValue, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(id))
            {
                continue;
            }

            var recordHost = NormalizeHost(name ?? string.Empty);
            if (recordHost != recordName && recordHost != GetRelativeName(recordName, zone) &&
                !recordHost.Equals($"{GetRelativeName(recordName, zone)}.{zone}", StringComparison.Ordinal))
            {
                continue;
            }

            var deleteBody = new Dictionary<string, object>
            {
                ["apikey"] = apiKey,
                ["secretapikey"] = apiSecret
            };
            var (status, response) = await PostAsync($"dns/delete/{zone}/{id}", deleteBody, cancellationToken).ConfigureAwait(false);
            if (!IsSuccess(response))
            {
                throw new InvalidOperationException($"Porkbun delete TXT failed ({status}): {TrimBody(response)}");
            }
        }
    }

    private static async Task<string> ResolveZoneAsync(
        string apiKey,
        string apiSecret,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (zone, _) = await RetrieveZoneAsync(apiKey, apiSecret, recordName, cancellationToken).ConfigureAwait(false);
        return zone;
    }

    private static async Task<(string Zone, string Body)> RetrieveZoneAsync(
        string apiKey,
        string apiSecret,
        string recordName,
        CancellationToken cancellationToken)
    {
        var auth = new Dictionary<string, object>
        {
            ["apikey"] = apiKey,
            ["secretapikey"] = apiSecret
        };

        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await PostAsync($"dns/retrieve/{candidate}", auth, cancellationToken).ConfigureAwait(false);
            if (status >= 200 && status < 300 && IsSuccess(body))
            {
                return (candidate, body);
            }
        }

        throw new InvalidOperationException($"Porkbun could not find a zone for '{recordName}'.");
    }

    private static async Task<(int Status, string Body)> PostAsync(
        string endpoint,
        Dictionary<string, object> body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/{endpoint}")
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-PorkbunDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        await Task.Delay(1000, cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, payload);
    }

    private static bool IsSuccess(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("status", out var status) &&
                   string.Equals(status.GetString(), "SUCCESS", StringComparison.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return body.Contains("\"status\":\"SUCCESS\"", StringComparison.OrdinalIgnoreCase);
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
