using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace DnsimpleDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class DnsimpleDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiBase = "https://api.dnsimple.com/v2";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "dnsimple",
        DisplayName = "DNSimple",
        Description = "DNS-01 via the DNSimple HTTP API using an account OAuth token."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "oauthToken",
            Label = "OAuth Token",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "DNSimple account access token"
        },
        new DnsCredentialField
        {
            Name = "accountId",
            Label = "Account ID",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional; required if the token can access multiple accounts"
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
        var token = GetRequired(credentials, "oauthToken");
        var accountId = await ResolveAccountIdAsync(token, GetOptional(credentials, "accountId"), cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, accountId, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);

        var existingId = await FindRecordIdAsync(token, accountId, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(existingId))
        {
            return;
        }

        var payload = JsonSerializer.Serialize(new
        {
            type = "TXT",
            name = relative,
            content = request.TxtValue,
            ttl = 120
        });

        var (status, body) = await SendAsync(
            HttpMethod.Post,
            $"{ApiBase}/{Uri.EscapeDataString(accountId)}/zones/{Uri.EscapeDataString(zone)}/records",
            token,
            payload,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"DNSimple add TXT failed ({status}): {TrimBody(body)}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var token = GetRequired(credentials, "oauthToken");
        var accountId = await ResolveAccountIdAsync(token, GetOptional(credentials, "accountId"), cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(token, accountId, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone);
        var recordId = await FindRecordIdAsync(token, accountId, zone, relative, request.TxtValue, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(recordId))
        {
            return;
        }

        var (status, body) = await SendAsync(
            HttpMethod.Delete,
            $"{ApiBase}/{Uri.EscapeDataString(accountId)}/zones/{Uri.EscapeDataString(zone)}/records/{Uri.EscapeDataString(recordId)}",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is not (200 or 204 or 404) && status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"DNSimple delete TXT failed ({status}): {TrimBody(body)}");
        }
    }

    private static async Task<string> ResolveAccountIdAsync(
        string token,
        string? accountId,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(accountId))
        {
            return accountId;
        }

        var (status, body) = await SendAsync(HttpMethod.Get, $"{ApiBase}/whoami", token, content: null, cancellationToken).ConfigureAwait(false);
        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"DNSimple whoami failed ({status}): {TrimBody(body)}");
        }

        using var whoami = JsonDocument.Parse(body);
        if (whoami.RootElement.TryGetProperty("data", out var data) &&
            data.TryGetProperty("account", out var account) &&
            account.ValueKind == JsonValueKind.Object)
        {
            var id = ReadId(account, "id");
            if (!string.IsNullOrWhiteSpace(id))
            {
                return id;
            }
        }

        var (accountsStatus, accountsBody) = await SendAsync(HttpMethod.Get, $"{ApiBase}/accounts", token, content: null, cancellationToken).ConfigureAwait(false);
        if (accountsStatus is < 200 or >= 300)
        {
            throw new InvalidOperationException($"DNSimple list accounts failed ({accountsStatus}): {TrimBody(accountsBody)}");
        }

        using var accounts = JsonDocument.Parse(accountsBody);
        var ids = new List<string>();
        if (accounts.RootElement.TryGetProperty("data", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in list.EnumerateArray())
            {
                var id = ReadId(item, "id");
                if (!string.IsNullOrWhiteSpace(id))
                {
                    ids.Add(id);
                }
            }
        }

        if (ids.Count == 1)
        {
            return ids[0];
        }

        if (ids.Count == 0)
        {
            throw new InvalidOperationException("DNSimple token is not associated with an account. Set Account ID.");
        }

        throw new InvalidOperationException(
            $"DNSimple token can access multiple accounts ({string.Join(", ", ids)}). Set Account ID.");
    }

    private static async Task<string> ResolveZoneAsync(
        string token,
        string accountId,
        string recordName,
        CancellationToken cancellationToken)
    {
        foreach (var candidate in CandidateZones(recordName))
        {
            var (status, _) = await SendAsync(
                HttpMethod.Get,
                $"{ApiBase}/{Uri.EscapeDataString(accountId)}/zones/{Uri.EscapeDataString(candidate)}",
                token,
                content: null,
                cancellationToken).ConfigureAwait(false);

            if (status is >= 200 and < 300)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException($"DNSimple could not find a zone for '{recordName}'.");
    }

    private static async Task<string?> FindRecordIdAsync(
        string token,
        string accountId,
        string zone,
        string relativeName,
        string txtValue,
        CancellationToken cancellationToken)
    {
        var (status, body) = await SendAsync(
            HttpMethod.Get,
            $"{ApiBase}/{Uri.EscapeDataString(accountId)}/zones/{Uri.EscapeDataString(zone)}/records?per_page=100&sort=id:desc",
            token,
            content: null,
            cancellationToken).ConfigureAwait(false);

        if (status is < 200 or >= 300)
        {
            throw new InvalidOperationException($"DNSimple list records failed ({status}): {TrimBody(body)}");
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("data", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var record in records.EnumerateArray())
        {
            var type = record.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
            var name = record.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var content = record.TryGetProperty("content", out var contentElement) ? contentElement.GetString() : null;
            var id = ReadId(record, "id");
            if (string.Equals(type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(NormalizeHost(name ?? string.Empty), relativeName, StringComparison.Ordinal) &&
                string.Equals(UnquoteTxt(content ?? string.Empty), txtValue, StringComparison.Ordinal) &&
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
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-DnsimpleDnsPlugin");
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
