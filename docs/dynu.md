# Dynu

In-app name: **Dynu**  
Release zip: `DynuDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_dynu.sh` against `https://api.dynu.com/v2`:

- Authenticate with OAuth (`GET /oauth2/token`, Basic client ID + secret, then `Authorization: Bearer`)
- Detect the zone with `GET /dns/getroot/{hostname}`
- Present: `POST /dns/{id}/record` TXT TTL 90 if that name/value is not already there
- Cleanup: list records, then `DELETE /dns/{id}/record/{recordId}`

Credentials:

- `clientId` — Dynu API client ID (required)
- `clientSecret` — Dynu API client secret (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
