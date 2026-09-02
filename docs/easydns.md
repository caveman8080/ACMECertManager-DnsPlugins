# EasyDNS

In-app name: **EasyDNS**  
Release zip: `EasyDnsDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_easydns.sh` against `https://rest.easydns.net`:

- Authenticate with HTTP Basic (`token:key`)
- Detect the zone by probing `GET /zones/records/all/{name}` (`"status":200`)
- Present: `PUT /zones/records/add/{zone}/TXT` (`host` + `rdata`) if that name/value is not already there (`"status":201` or already exists)
- Cleanup: `GET /zones/records/all/{zone}/search/{host}`, then `DELETE /zones/records/{zone}/{recordId}`

Credentials:

- `apiToken` — EasyDNS API token (`EASYDNS_Token`) (required)
- `apiKey` — EasyDNS API key (`EASYDNS_Key`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
