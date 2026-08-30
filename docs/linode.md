# Linode

In-app name: **Linode**  
Release zip: `LinodeDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_linode_v4.sh` against `https://api.linode.com/v4/domains`:

- Authenticate with `Authorization: Bearer`
- Detect the zone from `GET /domains`
- Present: `POST /{domainId}/records` TXT TTL 300 (`ttl_sec`) if that name/value is not already there
- Cleanup: list records and `DELETE /{domainId}/records/{recordId}`

Credentials:

- `apiKey` — Linode personal access token (`LINODE_V4_API_KEY`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
