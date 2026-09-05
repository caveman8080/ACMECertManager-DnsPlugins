# Loopia

In-app name: **Loopia**  
Release zip: `LoopiaDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_loopia.sh` against `https://api.loopia.se/RPCSERV` (or another Loopia TLD API URL):

- Authenticate with XML-RPC username and password on every call
- Detect the zone from `getDomains`
- Present: `addSubdomain` if needed, then `addZoneRecord` TXT TTL 300 if that name/value is not already there
- Cleanup: `getZoneRecords`, then `removeZoneRecord` for the matching TXT

Credentials:

- `username` — Loopia API username (`LOOPIA_User`) (required)
- `password` — Loopia API password (`LOOPIA_Password`) (required)
- `apiUrl` — optional API URL (`LOOPIA_Api`); default `https://api.loopia.se/RPCSERV` (also `.com`, `.no`, `.rs`)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create an API user in the Loopia customer zone. `AUTH_ERROR` is reported as authentication failure, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
