# Infomaniak

In-app name: **Infomaniak**  
Release zip: `InfomaniakDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_infomaniak.sh` against `https://api.infomaniak.com`:

- Authenticate with `Authorization: Bearer`
- Detect the zone from `GET /2/domains/{fqdn}/zones` (`fqdn`)
- Present: `POST /2/zones/{zone}/records` TXT TTL 300 if that name/value is not already there
- Cleanup: `GET /2/zones/{zone}/records`, then `DELETE /2/zones/{zone}/records/{recordId}`

Credentials:

- `apiToken` — Infomaniak API token (`INFOMANIAK_API_TOKEN`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create a token with scopes `domain:read`, `dns:read`, and `dns:write`.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
