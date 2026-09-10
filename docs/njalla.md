# Njalla

In-app name: **Njalla**  
Release zip: `NjallaDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_njalla.sh` against the Njalla JSON-RPC API `https://njal.la/api/1/`:

- Authenticate with `Authorization: Njalla {token}`
- Detect the zone with `get-domain` on each parent of the challenge FQDN
- Present: `add-record` TXT TTL 120 if that name/value is not already there
- Cleanup: `list-records`, then `remove-record` for the matching TXT id

Credentials:

- `apiToken` — Njalla API token (`NJALLA_Token`) from [Settings → API](https://njal.la/settings/api/) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Grant the token `get-domain`, `list-records`, `add-record`, and `remove-record`. HTTP 401/403 and JSON-RPC `Invalid token` are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
