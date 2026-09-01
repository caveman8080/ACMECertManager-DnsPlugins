# IONOS

In-app name: **IONOS**  
Release zip: `IonosDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_ionos.sh` against `https://api.hosting.ionos.com/dns`:

- Authenticate with `X-API-Key: {prefix}.{secret}`
- Detect the zone from `GET /v1/zones`
- Present: `POST /v1/zones/{id}/records` TXT TTL 60 if that name/value is not already there
- Cleanup: `GET /v1/zones/{id}?recordName={fqdn}&recordType=TXT`, then `DELETE /v1/zones/{id}/records/{recordId}`

Credentials:

- `apiPrefix` — IONOS API prefix (`IONOS_PREFIX`) (required)
- `apiSecret` — IONOS API secret (`IONOS_SECRET`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
