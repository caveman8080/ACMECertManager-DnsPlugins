using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace Ns1DnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class Ns1DnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.nsone.net/v1";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "ns1",
        DisplayName = "NS1",
        Description = "DNS-01 via the NS1 HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "NS1 API key (NS1_Key)"
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
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var answers = await GetTxtAnswersAsync(apiKey, zone, recordName, cancellationToken).ConfigureAwait(false);

        if (answers is not null &&
            answers.Any(value => string.Equals(UnquoteTxt(value), request.TxtValue, StringComparison.Ordinal)))
        {
            return;
        }

        var nextAnswers = new List<object>();
        if (answers is not null)
        {
            foreach (var value in answers)
            {
                nextAnswers.Add(new { answer = new[] { value } });
            }
        }

        nextAnswers.Add(new { answer = new[] { request.TxtValue } });

        var payload = JsonSerializer.Serialize(new
        {
            answers = nextAnswers,
            type = "TXT",
            domain = recordName,
            zone,
            ttl = 0
        });

        var method = answers is null ? HttpMethod.Put : HttpMethod.Post;
        var (status, body) = await SendAsync(
            method,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(recordName)}/TXT",
            apiKey,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is >= 200 and < 300 &&
            (body.Contains(recordName, StringComparison.OrdinalIgnoreCase) ||
             body.Contains("\"answers\"", StringComparison.Ordinal)))
        {
            return;
        }

        throw new InvalidOperationException($"NS1 add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiKey, recordName, cancellationToken).ConfigureAwait(false);
        var answers = await GetTxtAnswersAsync(apiKey, zone, recordName, cancellationToken).ConfigureAwait(false);
        if (answers is null)
        {
            return;
        }

        var remaining = answers
            .Where(value => !string.Equals(UnquoteTxt(value), request.TxtValue, StringComparison.Ordinal))
            .ToList();
        if (remaining.Count == answers.Count)
        {
            return;
        }

        if (remaining.Count == 0)
        {
            var (status, body) = await SendAsync(
                HttpMethod.Delete,
                $"{ApiBase}/zones/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(recordName)}/TXT",
                apiKey,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
            {
                throw new InvalidOperationException($"NS1 delete TXT failed ({status}): {TrimBody(body)}");
            }

            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            answers = remaining.Select(value => new { answer = new[] { value } }).ToArray(),
            type = "TXT",
            domain = recordName,
            zone,
            ttl = 0
        });

        var (updateStatus, updateBody) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(recordName)}/TXT",
            apiKey,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (updateStatus is < 200 or >= 300)
        {
            throw new InvalidOperationException($"NS1 update TXT failed ({updateStatus}): {TrimBody(updateBody)}");
        }
    }

    private static async Task<string> ResolveZoneAsync(
        string apiKey,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/zones",
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"NS1 list zones failed ({status}): {TrimBody(body)}");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        using (var doc = JsonDocument.Parse(body))
        {
            IEnumerable<JsonElement> zones = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray()
                : doc.RootElement.TryGetProperty("zones", out var wrapped) && wrapped.ValueKind == JsonValueKind.Array
                    ? wrapped.EnumerateArray()
                    : [];

            foreach (var zone in zones)
            {
                var name = zone.ValueKind == JsonValueKind.String
                    ? zone.GetString()
                    : zone.TryGetProperty("zone", out var zoneElement)
                        ? zoneElement.GetString()
                        : null;
                if (!string.IsNullOrWhiteSpace(name))
                {
                    names.Add(NormalizeHost(name));
                }
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            if (names.Contains(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"NS1 could not find a DNS zone for '{recordName}'.");
    }

    private static async Task<List<string>?> GetTxtAnswersAsync(
        string apiKey,
        string zone,
        string recordName,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/zones/{Uri.EscapeDataString(zone)}/{Uri.EscapeDataString(recordName)}/TXT",
            apiKey,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is 404 ||
            body.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("record not found", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"NS1 get TXT record failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("answers", out var answers) || answers.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var values = new List<string>();
        foreach (var answer in answers.EnumerateArray())
        {
            if (answer.TryGetProperty("answer", out var answerValues) && answerValues.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in answerValues.EnumerateArray())
                {
                    var value = item.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        values.Add(value);
                    }
                }
            }
        }

        return values;
    }

    private static async Task<(int Status, string Body)> SendAsync(
        HttpMethod method,
        string url,
        string apiKey,
        string? content,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("X-NSONE-Key", apiKey);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-Ns1DnsPlugin");
        if (content is not null)
        {
            request.Content = new StringContent(content, Encoding.UTF8, "application/json");
        }

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
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
