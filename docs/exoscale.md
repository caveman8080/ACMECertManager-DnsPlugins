# Exoscale DNS

In-app name: **Exoscale DNS**  
Release zip: `ExoscaleDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_exoscale.sh` against the Exoscale DNS HTTP API `https://api-ch-gva-2.exoscale.com/v2`:

- Authenticate with `EXO2-HMAC-SHA256` (API key + secret)
- Detect the zone from `GET /dns-domain` (`unicode-name`)
- Present: `POST /dns-domain/{id}/record` TXT TTL 120 if that name/value is not already there (HTTP 2xx)
- Cleanup: `GET /dns-domain/{id}/record`, then `DELETE /dns-domain/{id}/record/{record-id}`

Credentials:

- `apiKey` — Exoscale API key (`EXOSCALE_API_KEY`) (required)
- `apiSecret` — Exoscale API secret (`EXOSCALE_API_SECRET` / `EXOSCALE_SECRET_KEY`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create an IAM API key with DNS domain and record permissions. HTTP 401/403 are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
