# Hetzner DNS

In-app name: **Hetzner DNS**  
Release zip: `HetznerDnsPlugin-vMAJOR.MINOR.PATCH.zip`

Follows `acme.sh` `dns_hetzner.sh` against the console DNS API `https://dns.hetzner.com/api/v1` (not Hetzner Cloud DNS):

- Authenticate with `Auth-API-Token`
- Detect the zone with `GET /zones?name=`
- Present: `POST /records` TXT TTL 120 if that name/value is not already there
- Cleanup: `DELETE /records/{id}`

Credentials:

- `apiToken` — Hetzner DNS API token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
