# Cloudflare

In-app name: **Cloudflare**  
Release zip: `CloudflareDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_cf.sh` against `https://api.cloudflare.com/client/v4`:

- Authenticate with `Authorization: Bearer` (API token only; not Global API Key + email)
- Optional Zone ID; otherwise list zones by name until the record's zone is found
- Present: `POST /zones/{id}/dns_records` TXT TTL 120 (identical-record errors are success)
- Cleanup: find the TXT by name + content, then `DELETE /zones/{id}/dns_records/{recordId}`

Credentials:

- `apiToken` — Cloudflare API token with Zone.DNS Edit (required). Zone.Zone Read is needed if Zone ID is blank
- `zoneId` — optional Cloudflare zone identifier
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
