using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace NamecheapDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class NamecheapDnsValidationPlugin : IDnsValidationPlugin
{
    private const string ApiUrl = "https://api.namecheap.com/xml.response";
    private static readonly XNamespace Ns = "http://api.namecheap.com/xml.response";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "namecheap",
        DisplayName = "Namecheap",
        Description = "DNS-01 via the Namecheap HTTP XML API using API user, API key, and client IP when required."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "apiUser",
            Label = "API User",
            IsRequired = true,
            IsSecret = false,
            Placeholder = "Namecheap API user (account username)"
        },
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Namecheap API key"
        },
        new DnsCredentialField
        {
            Name = "clientIp",
            Label = "Client IP",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Whitelisted IPv4, or a URL that returns it (optional; auto-detected if blank)"
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
        var apiUser = GetRequired(credentials, "apiUser");
        var apiKey = GetRequired(credentials, "apiKey");
        var clientIp = await ResolveClientIpAsync(GetOptional(credentials, "clientIp"), cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiUser, apiKey, clientIp, recordName, cancellationToken).ConfigureAwait(false);

        var relative = GetRelativeName(recordName, zone.Domain);
        await MutateHostsAsync(
            apiUser,
            apiKey,
            clientIp,
            zone,
            hosts =>
            {
                hosts.Add(new HostRecord(relative, "TXT", request.TxtValue, "10", "120"));
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiUser = GetRequired(credentials, "apiUser");
        var apiKey = GetRequired(credentials, "apiKey");
        var clientIp = await ResolveClientIpAsync(GetOptional(credentials, "clientIp"), cancellationToken).ConfigureAwait(false);
        var recordName = NormalizeHost(request.RecordName);
        var zone = await ResolveZoneAsync(apiUser, apiKey, clientIp, recordName, cancellationToken).ConfigureAwait(false);
        var relative = GetRelativeName(recordName, zone.Domain);

        await MutateHostsAsync(
            apiUser,
            apiKey,
            clientIp,
            zone,
            hosts =>
            {
                hosts.RemoveAll(host =>
                    string.Equals(host.Type, "TXT", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(NormalizeHost(host.Name), NormalizeHost(relative), StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(host.Address, request.TxtValue, StringComparison.Ordinal));
            },
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task MutateHostsAsync(
        string apiUser,
        string apiKey,
        string clientIp,
        (string Domain, string Sld, string Tld) zone,
        Action<List<HostRecord>> mutate,
        CancellationToken cancellationToken)
    {
        var get = await CallAsync(
            apiUser,
            apiKey,
            clientIp,
            new Dictionary<string, string>
            {
                ["Command"] = "namecheap.domains.dns.getHosts",
                ["SLD"] = zone.Sld,
                ["TLD"] = zone.Tld
            },
            cancellationToken).ConfigureAwait(false);

        var result = get.Root?.Element(Ns + "CommandResponse")?.Element(Ns + "DomainDNSGetHostsResult");
        if (get.Root?.Attribute("Status")?.Value != "OK" || result is null)
        {
            throw new InvalidOperationException($"Namecheap getHosts failed: {GetError(get)}");
        }

        var hosts = new List<HostRecord>();
        foreach (var host in result.Elements(Ns + "host").Concat(result.Elements("host")))
        {
            hosts.Add(ParseHost(host));
        }

        mutate(hosts);

        var fields = new Dictionary<string, string>
        {
            ["Command"] = "namecheap.domains.dns.setHosts",
            ["SLD"] = zone.Sld,
            ["TLD"] = zone.Tld
        };

        for (var i = 0; i < hosts.Count; i++)
        {
            var n = i + 1;
            var host = hosts[i];
            fields[$"HostName{n}"] = host.Name;
            fields[$"RecordType{n}"] = host.Type;
            fields[$"Address{n}"] = host.Address;
            fields[$"MXPref{n}"] = host.MxPref;
            fields[$"TTL{n}"] = host.Ttl;
        }

        var set = await CallAsync(apiUser, apiKey, clientIp, fields, cancellationToken).ConfigureAwait(false);
        if (set.Root?.Attribute("Status")?.Value != "OK")
        {
            throw new InvalidOperationException($"Namecheap setHosts failed: {GetError(set)}");
        }
    }

    private static async Task<(string Domain, string Sld, string Tld)> ResolveZoneAsync(
        string apiUser,
        string apiKey,
        string clientIp,
        string recordName,
        CancellationToken cancellationToken)
    {
        var owned = await ListOurDnsDomainsAsync(apiUser, apiKey, clientIp, cancellationToken).ConfigureAwait(false);
        foreach (var candidate in CandidateZones(recordName))
        {
            if (owned.Contains(candidate))
            {
                return await SplitSldTldAsync(apiUser, apiKey, clientIp, candidate, cancellationToken).ConfigureAwait(false);
            }
        }

        foreach (var candidate in CandidateZones(recordName))
        {
            if (await TryGetHostsAsync(apiUser, apiKey, clientIp, candidate, cancellationToken).ConfigureAwait(false) is { } split)
            {
                return split;
            }
        }

        throw new InvalidOperationException($"Namecheap could not find a DNS zone for '{recordName}'.");
    }

    private static async Task<HashSet<string>> ListOurDnsDomainsAsync(
        string apiUser,
        string apiKey,
        string clientIp,
        CancellationToken cancellationToken)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var page = 1;
        while (page <= 50)
        {
            var doc = await CallAsync(
                apiUser,
                apiKey,
                clientIp,
                new Dictionary<string, string>
                {
                    ["Command"] = "namecheap.domains.getList",
                    ["ListType"] = "ALL",
                    ["Page"] = page.ToString(),
                    ["PageSize"] = "100"
                },
                cancellationToken).ConfigureAwait(false);

            if (doc.Root?.Attribute("Status")?.Value != "OK")
            {
                break;
            }

            var domains = doc.Descendants(Ns + "Domain").Concat(doc.Descendants("Domain"));
            var count = 0;
            foreach (var domain in domains)
            {
                count++;
                var name = domain.Attribute("Name")?.Value;
                var ourDns = domain.Attribute("IsOurDNS")?.Value;
                if (!string.IsNullOrWhiteSpace(name) &&
                    string.Equals(ourDns, "true", StringComparison.OrdinalIgnoreCase))
                {
                    names.Add(NormalizeHost(name));
                }
            }

            var totalItems = doc.Descendants(Ns + "TotalItems").Concat(doc.Descendants("TotalItems")).FirstOrDefault()?.Value;
            if (count == 0)
            {
                break;
            }

            if (int.TryParse(totalItems, out var total) && names.Count >= total)
            {
                break;
            }

            if (count < 100)
            {
                break;
            }

            page++;
        }

        return names;
    }

    private static async Task<(string Domain, string Sld, string Tld)?> TryGetHostsAsync(
        string apiUser,
        string apiKey,
        string clientIp,
        string domain,
        CancellationToken cancellationToken)
    {
        try
        {
            return await SplitSldTldAsync(apiUser, apiKey, clientIp, domain, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static async Task<(string Domain, string Sld, string Tld)> SplitSldTldAsync(
        string apiUser,
        string apiKey,
        string clientIp,
        string domain,
        CancellationToken cancellationToken)
    {
        var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 1; i < labels.Length; i++)
        {
            var sld = string.Join('.', labels.Take(i));
            var tld = string.Join('.', labels.Skip(i));
            if (string.IsNullOrWhiteSpace(sld) || string.IsNullOrWhiteSpace(tld))
            {
                continue;
            }

            var doc = await CallAsync(
                apiUser,
                apiKey,
                clientIp,
                new Dictionary<string, string>
                {
                    ["Command"] = "namecheap.domains.dns.getHosts",
                    ["SLD"] = sld,
                    ["TLD"] = tld
                },
                cancellationToken).ConfigureAwait(false);

            if (doc.Root?.Attribute("Status")?.Value == "OK" &&
                (doc.Descendants(Ns + "DomainDNSGetHostsResult").Any() || doc.Descendants("DomainDNSGetHostsResult").Any()))
            {
                return (domain, sld, tld);
            }
        }

        throw new InvalidOperationException($"Namecheap getHosts did not accept SLD/TLD splits for '{domain}'.");
    }

    private static async Task<XDocument> CallAsync(
        string apiUser,
        string apiKey,
        string clientIp,
        Dictionary<string, string> extra,
        CancellationToken cancellationToken)
    {
        var fields = new Dictionary<string, string>(extra)
        {
            ["ApiUser"] = apiUser,
            ["ApiKey"] = apiKey,
            ["UserName"] = apiUser,
            ["ClientIp"] = clientIp
        };

        using var content = new FormUrlEncodedContent(fields);
        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUrl) { Content = content };
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NamecheapDnsPlugin");

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Namecheap API request failed with {(int)response.StatusCode}: {TrimBody(payload)}");
        }

        try
        {
            return XDocument.Parse(payload);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Namecheap returned invalid XML: {TrimBody(payload)}", ex);
        }
    }

    private static async Task<string> ResolveClientIpAsync(string? clientIp, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            if (Regex.IsMatch(clientIp, @"^\d{1,3}(\.\d{1,3}){3}$"))
            {
                return clientIp;
            }

            if (clientIp.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                clientIp.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return await FetchIpAsync(clientIp, cancellationToken).ConfigureAwait(false);
            }

            throw new InvalidOperationException("Client IP must be an IPv4 address or a URL that returns one.");
        }

        return await FetchIpAsync("https://api.ipify.org", cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> FetchIpAsync(string url, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("User-Agent", "ACMECertManager-NamecheapDnsPlugin");
        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var payload = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
        var match = Regex.Match(payload, @"\d{1,3}(\.\d{1,3}){3}");
        if (!match.Success)
        {
            throw new InvalidOperationException($"Could not determine Namecheap client IP from '{url}'. Set Client IP to your whitelisted IPv4.");
        }

        return match.Value;
    }

    private static HostRecord ParseHost(XElement host)
    {
        return new HostRecord(
            host.Attribute("Name")?.Value ?? "@",
            host.Attribute("Type")?.Value ?? "A",
            host.Attribute("Address")?.Value ?? string.Empty,
            string.IsNullOrWhiteSpace(host.Attribute("MXPref")?.Value) ? "10" : host.Attribute("MXPref")!.Value,
            string.IsNullOrWhiteSpace(host.Attribute("TTL")?.Value) ? "1800" : host.Attribute("TTL")!.Value);
    }

    private static string GetError(XDocument doc)
    {
        var error = doc.Descendants(Ns + "Error").Concat(doc.Descendants("Error")).FirstOrDefault()?.Value;
        return string.IsNullOrWhiteSpace(error) ? "(no error text)" : error.Trim();
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

    private readonly record struct HostRecord(string Name, string Type, string Address, string MxPref, string Ttl);
}
