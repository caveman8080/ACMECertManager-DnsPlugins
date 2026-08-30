# ClouDNS

In-app name: **ClouDNS**  
Release zip: `CloudnsDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_cloudns.sh` against `https://api.cloudns.net`:

- Authenticate with `auth-id` or `sub-auth-id` plus `auth-password` (`GET /dns/login.json`)
- Detect the zone with `GET /dns/get-zone-info.json` (cloud zones use `cloud-master`)
- Present: `GET /dns/add-record.json` TXT TTL 60 if that name/value is not already there
- Cleanup: `GET /dns/records.json` then `GET /dns/delete-record.json`

Credentials:

- `authId` — regular API auth ID. Required unless sub-auth ID is set
- `subAuthId` — optional sub-auth ID; used instead of Auth ID when set
- `authPassword` — ClouDNS API password (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
