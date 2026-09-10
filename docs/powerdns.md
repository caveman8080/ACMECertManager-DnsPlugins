# PowerDNS

In-app name: **PowerDNS**  
Release zip: `PowerDnsDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_pdns.sh` against the PowerDNS Authoritative HTTP API (`/api/v1/servers/{server}/zones`):

- Authenticate with `X-API-Key`
- Detect the zone from `GET /api/v1/servers/{serverId}/zones`
- Present: `PATCH` the zone rrset (`changetype: REPLACE`) with a TXT TTL 60 if that name/value is not already there
- Cleanup: `PATCH` the zone rrset (`changetype: DELETE`, or `REPLACE` remaining TXT values)

Credentials:

- `apiBaseUrl` — PowerDNS API origin, e.g. `https://pdns.example:8081` (required)
- `apiKey` — API key sent as `X-API-Key` (required)
- `serverId` — server id in the API path (optional, default `localhost`)
- `propagationSeconds` — optional wait before ACME validation (default 30)

HTTP 401/403 are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
