# No-IP

In-app name: **No-IP**  
Release zip: `NoIpDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Uses the official No-IP DNS HTTP API `https://api.noip.com/v1` (there is no `acme.sh` `dns_noip.sh`):

- Authenticate with `Authorization: Bearer {apiKey}` (HTTP Basic with a blank username is also accepted by No-IP)
- Detect the zone with `GET /dns/zones/{name}`
- Present: `POST /dns/records/{zone}/{name}/rrsets/TXT/rdata`, then `POST .../publish`
- Cleanup: `GET /dns/records/{zone}/{name}/rrsets/TXT`, then `DELETE .../rdata/{label}` for the matching value

**This is the 2024 No-IP DNS API, not the older Dynupdate `/nic/update` endpoint (A/AAAA only).** Dynupdate credentials will not work — use a DNS API key from account API key management.

Credentials:

- `apiKey` — No-IP DNS API key from the [API Key management page](https://www.noip.com/) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
