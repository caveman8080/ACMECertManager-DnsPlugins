# Hostinger

In-app name: **Hostinger**  
Release zip: `HostingerDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_hostinger.sh` against `https://developers.hostinger.com/api/dns/v1/zones`:

- Authenticate with `Authorization: Bearer {token}`
- Detect the zone with `GET /{domain}` (JSON array of record sets)
- Present: `PUT /{zone}` TXT TTL 120 with `overwrite: false`
- Cleanup: read remaining TXT values; `PUT` with `overwrite: true` if others remain, otherwise `DELETE` with `filters` for that name and type

Credentials:

- `apiToken` — Hostinger API token (`HOSTINGER_Token`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create a token at [developers.hostinger.com](https://developers.hostinger.com/) with DNS zone read/write.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
