# GoDaddy

In-app name: **GoDaddy**  
Release zip: `GoDaddyDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_gd.sh` against `https://api.godaddy.com/v1`:

- Authenticate with `Authorization: sso-key {key}:{secret}`
- Detect the zone by probing `GET /domains/{zone}/records/TXT/{name}` (JSON array) or `GET /domains/{zone}`
- Present: read existing TXT values for the name, then `PUT` the merged list
- Cleanup: `PUT` the remaining values, or `DELETE` the name if that was the last TXT

Credentials:

- `apiKey` — GoDaddy API key (required)
- `apiSecret` — GoDaddy API secret (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
