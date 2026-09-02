using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text.Json;

namespace DreamHostDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DreamHostDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.dreamhost.com/";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "dreamhost",
        DisplayName = "DreamHost",
        Description = "DNS-01 via the DreamHost HTTP API using an API key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "DreamHost API key (DH_API_KEY)"
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
        var (status, body) = await CallAsync(
            apiKey,
            "dns-add_record",
            recordName,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);

        if (IsResult(body, "success") ||
            ContainsData(body, "record_already_exists"))
        {
            return;
        }

        throw new InvalidOperationException($"DreamHost add TXT failed ({status}): {TrimBody(body)}");
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = GetRequired(credentials, "apiKey");
        var recordName = NormalizeHost(request.RecordName);
        var (status, body) = await CallAsync(
            apiKey,
            "dns-remove_record",
            recordName,
            request.TxtValue,
            cancellationToken).ConfigureAwait(false);

        if (status is 404 ||
            IsResult(body, "success") ||
            ContainsData(body, "no_record") ||
            ContainsData(body, "no_such") ||
            ContainsData(body, "record_not_found") ||
            ContainsData(body, "no_such_record"))
        {
            return;
        }

        if (status is < 200 or >= 300 || IsResult(body, "error"))
        {
            throw new InvalidOperationException($"DreamHost delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<(int Status, string Body)> CallAsync(
        string apiKey,
        string command,
        string recordName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var url =
            $"{ApiBase}?key={Uri.EscapeDataString(apiKey)}" +
            $"&cmd={Uri.EscapeDataString(command)}" +
            $"&record={Uri.EscapeDataString(recordName)}" +
            "&type=TXT" +
            $"&value={Uri.EscapeDataString(txtValue)}" +
            "&format=json";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DreamHostDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static bool IsResult(string body, string expected)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var result = doc.RootElement.TryGetProperty("result", out var resultElement)
                ? resultElement.GetString()
                : null;
            if (string.Equals(result, expected, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        catch (JsonException)
        {
            // Fall through to raw-body matching.
        }

        return body.Contains($"\"result\":\"{expected}\"", StringComparison.OrdinalIgnoreCase) ||
               body.Contains($"\"result\": \"{expected}\"", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsData(string body, string needle)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("data", out var data))
            {
                var text = data.ValueKind == JsonValueKind.String ? data.GetString() : data.GetRawText();
                if (text is not null && text.Contains(needle, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch (JsonException)
        {
            // Fall through to raw-body matching.
        }

        return body.Contains(needle, StringComparison.OrdinalIgnoreCase);
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
