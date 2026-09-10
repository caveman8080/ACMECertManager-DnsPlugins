# hosting.de

In-app name: **hosting.de**  
Release zip: `HostingDeDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_hostingde.sh` against the hosting.de DNS JSON API `https://secure.hosting.de/api/dns/v1/json`:

- Authenticate with `authToken` in the JSON body
- Detect the zone with `POST /zoneConfigsFind` (`filter.field` = `ZoneName`)
- Present: `POST /zoneUpdate` `recordsToAdd` TXT TTL 60 if that name/value is not already there (`recordsFind`)
- Cleanup: `POST /zoneUpdate` `recordsToDelete` for the matching record id

Credentials:

- `authToken` — hosting.de API token (`HOSTINGDE_APIKEY`) (required). Create a key at [secure.hosting.de](https://secure.hosting.de) with `DNS_ZONES_LIST` and `DNS_ZONES_EDIT`
- `propagationSeconds` — optional wait before ACME validation (default 30)

HTTP 401/403 and API error `10109` (invalid API key) are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
