using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace DynuDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DynuDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.dynu.com/v2";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "dynu",
        DisplayName = "Dynu",
        Description = "DNS-01 via the Dynu HTTP API using OAuth client ID and secret."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "clientId",
            Label = "Client ID",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Dynu API client ID"
        },
        new DnsCredentialField
        {
            Name = "clientSecret",
            Label = "Client Secret",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Dynu API client secret"
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
        var token = await AuthenticateAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var node = GetRelativeName(recordName, zone.Name);

        var existingId = await FindRecordIdAsync(token, zone.Id, node, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            domainId = zone.Id,
            nodeName = node,
            recordType = "TXT",
            textData = request.TxtValue,
            state = true,
            ttl = 90
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/dns/{Uri.EscapeDataString(zone.Id)}/record",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300 || !IsDynuSuccess(body))
        {
            throw new InvalidOperationException($"Dynu add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = await AuthenticateAsync(credentials, cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, recordName, cancellationToken).ConfigureAwait(false);
        var node = GetRelativeName(recordName, zone.Name);
        var recordId = await FindRecordIdAsync(token, zone.Id, node, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/dns/{Uri.EscapeDataString(zone.Id)}/record/{Uri.EscapeDataString(recordId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && (status is < 200 or >= 300 || !IsDynuSuccess(body)))
        {
            throw new InvalidOperationException($"Dynu delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<string> AuthenticateAsync(
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var clientId = GetRequired(credentials, "clientId");
        var clientSecret = GetRequired(credentials, "clientSecret");
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{ApiBase}/oauth2/token");
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {basic}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DynuDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Dynu OAuth token request failed ({(int)response.StatusCode}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        var token = doc.RootElement.TryGetProperty("access_token", out var tokenElement)
            ? tokenElement.GetString()
            : null;
        if (string.IsNullOrWhiteSpace(token) || token == "null")
        {
            throw new InvalidOperationException($"Dynu OAuth token request did not return access_token: {TrimBody(body)}");
        }

        return token;
    }

    private static async Task<(string Id, string Name)> ResolveZoneAsync(
        string token,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/dns/getroot/{Uri.EscapeDataString(candidate)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300 || !IsDynuSuccess(body))
            {
                continue;
            }

            using var doc = JsonDocument.Parse(body);
            var name = doc.RootElement.TryGetProperty("domainName", out var nameElement)
                ? nameElement.GetString()
                : null;
            var id = ReadId(doc.RootElement, "id");
            if (!string.IsNullOrWhiteSpace(id) &&
                string.Equals(NormalizeHost(name ?? string.Empty), candidate, StringComparison.Ordinal))
            {
                return (id, candidate);
            }
        }

        throw new InvalidOperationException($"Dynu could not find a zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string token,
        string zoneId,
        string nodeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/dns/{Uri.EscapeDataString(zoneId)}/record",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Dynu list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("dnsRecords", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = record.TryGetProperty("recordType", out var typeElement) ? typeElement.GetString() : null;
            var node = record.TryGetProperty("nodeName", out var nodeElement) ? nodeElement.GetString() : null;
            var text = record.TryGetProperty("textData", out var textElement) ? textElement.GetString() : null;
            if (string.IsNullOrWhiteSpace(text) && record.TryGetProperty("content", out var contentElement))
            {
                text = contentElement.GetString();
            }

            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                NamesEqual(node, nodeName) &&
                string.Equals(UnquoteTxt(text ?? string.Empty), txtValue, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        return null;
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string token,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DynuDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static bool IsDynuSuccess(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("statusCode", out var code) && code.TryGetInt32(out var value))
            {
                return value is >= 200 and < 300;
            }
        }
        catch (JsonException)
        {
            // Fall through to HTTP-status handling at the call site.
        }

        return false;
    }

    private static bool NamesEqual(string? left, string right)
    {
        var a = NormalizeHost(left ?? string.Empty);
        var b = NormalizeHost(right);
        return a == b || (string.IsNullOrEmpty(a) && (string.IsNullOrEmpty(b) || b == "@")) ||
               (string.IsNullOrEmpty(b) && (string.IsNullOrEmpty(a) || a == "@"));
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

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static string TrimBody(string body)
    {
        var trimmed = body.Trim();
        return trimmed.Length <= 500 ? trimmed : trimmed[..500];
    }
}
