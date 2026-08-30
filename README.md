# ACMECertManager DNS-01 Plugins

Downloadable DNS-01 plugins for [ACMECertManager](https://github.com/caveman8080/ACMECertManager).

ACMECertManager loads provider DLLs from `plugins/` next to `acm.exe`. This repo ships **one zip per plugin** so you only download the provider you use.

## Install (download and drop)

1. Install [ACMECertManager](https://github.com/caveman8080/ACMECertManager/releases).
2. Open this repo's [Releases](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases) and download the zip for the plugin you want.
3. Extract the plugin DLL into `ACMECertManager/plugins/` (the folder beside `acm.exe`).
4. Restart ACMECertManager.
5. Issue a certificate with **DNS-01 (plugin)** and select the provider.

Do not copy `acm.exe` or other host files into `plugins/`. Each release zip contains only that plugin's DLL.

## Plugins

| Plugin | Release zip | In-app name |
| --- | --- | --- |
| [Hurricane Electric DDNS](#hurricane-electric-ddns) | `HurricaneElectricDnsPlugin-vMAJOR.MINOR.PATCH.zip` | Hurricane Electric - DDNS |
| [Cloudflare](#cloudflare) | `CloudflareDnsPlugin-vMAJOR.MINOR.PATCH.zip` | Cloudflare |
| [DuckDNS](#duckdns) | `DuckDnsDnsPlugin-vMAJOR.MINOR.PATCH.zip` | DuckDNS |
| [Porkbun](#porkbun) | `PorkbunDnsPlugin-vMAJOR.MINOR.PATCH.zip` | Porkbun |
| [DigitalOcean](#digitalocean) | `DigitalOceanDnsPlugin-vMAJOR.MINOR.PATCH.zip` | DigitalOcean |
| [Hetzner DNS](#hetzner-dns) | `HetznerDnsPlugin-vMAJOR.MINOR.PATCH.zip` | Hetzner DNS |
| [GoDaddy](#godaddy) | `GoDaddyDnsPlugin-vMAJOR.MINOR.PATCH.zip` | GoDaddy |
| [Namecheap](#namecheap) | `NamecheapDnsPlugin-vMAJOR.MINOR.PATCH.zip` | Namecheap |
| [deSEC](#desec) | `DesecDnsPlugin-vMAJOR.MINOR.PATCH.zip` | deSEC |

These plugins talk to each provider over HTTP. AWS Route53, Azure DNS, and Google Cloud DNS are out of scope (they need official SDKs).

Every plugin exposes optional `propagationSeconds` (default 30), same as Hurricane Electric. Credentials are stored by the host app in plaintext (`storage/dns-secrets.json`).

## Request a plugin

Missing a DNS provider? Open a [plugin request](https://github.com/caveman8080/ACMECertManager-DnsPlugins/issues/new?template=plugin-request.yml) issue. See [CONTRIBUTING.md](CONTRIBUTING.md) for the request form and how maintainers add a plugin under `src/`.

## Plugin contract

ACMECertManager discovers plugins with `typeof(IDnsValidationPlugin).IsAssignableFrom` on `*.dll` files in `plugins/`. That type lives in the **app assembly** (`src/DnsPlugins.cs`, namespace `ACMECertManager`). A second copy of the interface in a plugin assembly will not load.

**Contract 1** is the current ACMECertManager `main` interface:

```csharp
public interface IDnsValidationPlugin
{
    DnsPluginMetadata Metadata { get; }
    IReadOnlyList<DnsCredentialField> GetCredentialFields();
    Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken);
    Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken);
}
```

Related contract types (same assembly): `DnsPluginMetadata`, `DnsCredentialField`, `DnsChallengeRequest`.

Plugins in this repo **ProjectReference** `ACMECertManager/src/ACMECertManager.csproj`. They do not redefine `IDnsValidationPlugin`.

If the host interface changes in a breaking way, this archive will document a new contract version.

## Hurricane Electric DDNS

Ported from the ACMECertManager sample (`samples/HurricaneElectricDnsPlugin`). It follows the same high-level flow as `acme.sh` `dns_he_ddns.sh`:

- Update TXT through `https://dyn.dns.he.net/nic/update`
- Send `hostname`, `password` (DDNS key), and `txt`
- Treat `good` and `nochg` responses as success
- Cleanup is a no-op because HE DDNS updates the same record target

Credentials (entered in ACMECertManager):

- `ddnsKey` — Hurricane Electric DDNS key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

This plugin targets HE DDNS, not the dns.he.net zone-edit form API.

## Cloudflare

Follows `acme.sh` `dns_cf.sh` against `https://api.cloudflare.com/client/v4`:

- Authenticate with `Authorization: Bearer` (API token only; not Global API Key + email)
- Optional Zone ID; otherwise list zones by name until the record's zone is found
- Present: `POST /zones/{id}/dns_records` TXT TTL 120 (identical-record errors are success)
- Cleanup: find the TXT by name + content, then `DELETE /zones/{id}/dns_records/{recordId}`

Credentials:

- `apiToken` — Cloudflare API token with Zone.DNS Edit (required). Zone.Zone Read is needed if Zone ID is blank
- `zoneId` — optional Cloudflare zone identifier
- `propagationSeconds` — optional wait before ACME validation (default 30)

## DuckDNS

Follows `acme.sh` `dns_duckdns.sh` against `https://www.duckdns.org/update`:

- Present: `GET` with `domains`, `token`, and `txt`
- Cleanup: `GET` with `txt=` and `clear=true` (DuckDNS has one TXT slot per domain)
- The DuckDNS subdomain is taken from the record name (`*.duckdns.org`)

Credentials:

- `token` — DuckDNS account token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

## Porkbun

Follows `acme.sh` `dns_porkbun.sh` against `https://api.porkbun.com/api/json/v3`:

- Auth fields `apikey` and `secretapikey` on every JSON POST
- Detect the zone with `dns/retrieve/{domain}`
- Present: `dns/create/{domain}` TXT TTL 120
- Cleanup: match the TXT in the retrieve list, then `dns/delete/{domain}/{id}`

Credentials:

- `apiKey` — Porkbun API key (required)
- `apiSecret` — Porkbun secret API key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

## DigitalOcean

Follows `acme.sh` `dns_dgon.sh` against `https://api.digitalocean.com/v2`:

- Authenticate with `Authorization: Bearer`
- Detect the zone with `GET /domains/{name}`
- Present: `POST /domains/{zone}/records` TXT TTL 120
- Cleanup: list records (including extra pages) and `DELETE` the matching TXT

Credentials:

- `apiToken` — DigitalOcean personal access token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

## Hetzner DNS

Follows `acme.sh` `dns_hetzner.sh` against the console DNS API `https://dns.hetzner.com/api/v1` (not Hetzner Cloud DNS):

- Authenticate with `Auth-API-Token`
- Detect the zone with `GET /zones?name=`
- Present: `POST /records` TXT TTL 120 if that name/value is not already there
- Cleanup: `DELETE /records/{id}`

Credentials:

- `apiToken` — Hetzner DNS API token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

## GoDaddy

Follows `acme.sh` `dns_gd.sh` against `https://api.godaddy.com/v1`:

- Authenticate with `Authorization: sso-key {key}:{secret}`
- Detect the zone by probing `GET /domains/{zone}/records/TXT/{name}` (JSON array) or `GET /domains/{zone}`
- Present: read existing TXT values for the name, then `PUT` the merged list
- Cleanup: `PUT` the remaining values, or `DELETE` the name if that was the last TXT

Credentials:

- `apiKey` — GoDaddy API key (required)
- `apiSecret` — GoDaddy API secret (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

## Namecheap

Follows `acme.sh` `dns_namecheap.sh` against `https://api.namecheap.com/xml.response`.

Namecheap `setHosts` **replaces the whole host list**. The plugin reads every existing host with `domains.dns.getHosts`, then writes the full list back with the challenge TXT added or removed.

Credentials:

- `apiUser` — Namecheap API user (required)
- `apiKey` — Namecheap API key (required)
- `clientIp` — IPv4 that Namecheap has allowlisted, or a URL that returns that IPv4. Optional; if blank the plugin fetches `https://api.ipify.org`
- `propagationSeconds` — optional wait before ACME validation (default 30)

Enable API access in the Namecheap account and allowlist the client IP.

## deSEC

Follows `acme.sh` `dns_desec.sh` against `https://desec.io/api/v1/domains`:

- Authenticate with `Authorization: Token`
- Detect the zone from `GET /domains/`
- Present/cleanup: `PUT /domains/{zone}/rrsets/` with the merged TXT RRset (TTL 3600)

Credentials:

- `apiToken` — deSEC API token (`DEDYN_TOKEN`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

## Build from source

Plugins compile against the real `IDnsValidationPlugin` type in ACMECertManager. Clone the app next to this tree (or add it as a submodule) so `ACMECertManager/src/ACMECertManager.csproj` exists.

**Clone both** (app checkout inside this repo — same layout CI uses):

```powershell
git clone https://github.com/caveman8080/ACMECertManager-DnsPlugins.git
cd ACMECertManager-DnsPlugins
git clone https://github.com/caveman8080/ACMECertManager.git ACMECertManager
dotnet build ACMECertManager.DnsPlugins.sln -c Release
```

**Clone both as siblings**, then junction or symlink the app in:

```powershell
git clone https://github.com/caveman8080/ACMECertManager.git
git clone https://github.com/caveman8080/ACMECertManager-DnsPlugins.git
cd ACMECertManager-DnsPlugins
cmd /c mklink /J ACMECertManager ..\ACMECertManager
dotnet build ACMECertManager.DnsPlugins.sln -c Release
```

**Submodule** (optional; remove `/ACMECertManager/` from `.gitignore` first):

```powershell
git submodule add https://github.com/caveman8080/ACMECertManager.git ACMECertManager
dotnet build ACMECertManager.DnsPlugins.sln -c Release
```

Minimum SDK/runtime: .NET 10 (`net10.0-windows`). After a Release build, copy each `src/<Name>DnsPlugin/bin/Release/net10.0-windows/<Name>DnsPlugin.dll` into `plugins/`. Do not copy `acm.exe`.

## Releases

Push a tag `vMAJOR.MINOR.PATCH` (for example `v1.0.0`). GitHub Actions builds each plugin under `src/` and uploads one zip per plugin. The zip contains only that plugin's DLL.

## License

GPL v3, same as [ACMECertManager](https://github.com/caveman8080/ACMECertManager). See [LICENSE](LICENSE).
