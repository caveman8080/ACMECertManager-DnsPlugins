# Bunny.net DNS

In-app name: **Bunny.net DNS**  
Release zip: `BunnyDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_bunny.sh` against `https://api.bunny.net`:

- Authenticate with `AccessKey`
- Detect the zone from `GET /dnszone` (including extra pages)
- Present: `PUT /dnszone/{id}/records` TXT (type 3) TTL 120 if that name/value is not already there
- Cleanup: read the zone records, then `DELETE /dnszone/{id}/records/{recordId}`

Credentials:

- `apiKey` — Bunny.net account API key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
