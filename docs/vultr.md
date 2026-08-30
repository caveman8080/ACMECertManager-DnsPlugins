# Vultr

In-app name: **Vultr**  
Release zip: `VultrDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_vultr.sh` against `https://api.vultr.com/v2`:

- Authenticate with `Authorization: Bearer`
- Detect the zone from `GET /domains`
- Present: `POST /domains/{zone}/records` TXT TTL 120 if that name/value is not already there
- Cleanup: list records and `DELETE /domains/{zone}/records/{recordId}`

Credentials:

- `apiKey` — Vultr API key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
