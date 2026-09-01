using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace NameComDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class NameComDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.name.com/v4";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "namecom",
        DisplayName = "Name.com",
        Description = "DNS-01 via the Name.com HTTP API v4 using username and API token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "username",
            Label = "Username",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "Name.com account username"
        },
        new DnsCredentialField
        {
            Name = "apiToken",
            Label = "API Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Name.com API token"
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
        var username = GetRequired(credentials, "username");
        var apiToken = GetRequired(credentials, "apiToken");
        await LoginAsync(username, apiToken, cancellationToken).ConfigureAwait(false);

        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(username, apiToken, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existingId = await FindRecordIdAsync(username, apiToken, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            host = relative,
            type = "TXT",
            answer = request.TxtValue,
            ttl = 300
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records",
            username,
            apiToken,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Name.com add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var username = GetRequired(credentials, "username");
        var apiToken = GetRequired(credentials, "apiToken");
        await LoginAsync(username, apiToken, cancellationToken).ConfigureAwait(false);

        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(username, apiToken, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(username, apiToken, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(recordId)}",
            username,
            apiToken,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Name.com delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task LoginAsync(string username, string apiToken, CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/hello",
            username,
            apiToken,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 401 or 403)
        {
            throw new InvalidOperationException(
                $"Name.com login failed ({status}): check username/token and whitelist this machine's IP. {TrimBody(body)}");
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"Name.com login failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<string> ResolveZoneAsync(
        string username,
        string apiToken,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(candidate)}",
                username,
                apiToken,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is 404)
            {
                continue;
            }

            if (status is < 200 or >= 300)
            {
                continue;
            }

            if (body.Contains($"\"domainName\":\"{candidate}\"", StringComparison.OrdinalIgnoreCase) ||
                body.Contains($"\"domainName\": \"{candidate}\"", StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                var name = doc.RootElement.TryGetProperty("domainName", out var nameElement) ? nameElement.GetString() : null;
                if (string.Equals(NormalizeHost(name ?? string.Empty), candidate, StringComparison.Ordinal))
                {
                    return candidate;
                }
            }
            catch (JsonException)
            {
                // Not a domain payload; try the next candidate.
            }
        }

        throw new InvalidOperationException($"Name.com could not find a domain zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string username,
        string apiToken,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var page = 1;
        while (true)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/domains/{Uri.EscapeDataString(zone)}/records?perPage=1000&page={page}",
                username,
                apiToken,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"Name.com list records failed ({status}): {TrimBody(body)}");
            }

            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("records", out var records) && records.ValueKind == JsonValueKind.Array)
            {
                foreach (var record in records.EnumerateArray())
                {
                    var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                    var host = record.TryGetProperty("host", out var hostElement) ? hostElement.GetString() : null;
                    var answer = record.TryGetProperty("answer", out var answerElement) ? answerElement.GetString() : null;
                    var id = ReadId(record, "id");
                    var normalizedHost = NormalizeHost(host ?? string.Empty);
                    if (normalizedHost == "@")
                    {
                        normalizedHost = "";
                    }

                    if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(normalizedHost, relativeName, StringComparison.Ordinal) &&
                        string.Equals(UnquoteTxt(answer ?? string.Empty), txtValue, StringComparison.Ordinal) &&
                        !string.IsNullOrWhiteSpace(id))
                    {
                        return id;
                    }
                }
            }

            if (doc.RootElement.TryGetProperty("nextPage", out var next) &&
                next.TryGetInt32(out var nextPage) &&
                nextPage > page)
            {
                page = nextPage;
                continue;
            }

            return null;
        }
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string username,
        string apiToken,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{apiToken}"));
        request.Headers.TryAddWithoutValidation("Authorization", $"Basic {basic}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NameComDnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
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
