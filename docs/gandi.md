# Gandi LiveDNS

In-app name: **Gandi LiveDNS**  
Release zip: `GandiDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_gandi_livedns.sh` against `https://api.gandi.net/v5/livedns`:

- Authenticate with `Authorization: Bearer` (personal access token) or deprecated `Authorization: Apikey`
- Detect the zone with `GET /domains/{fqdn}`
- Present/cleanup: merge TXT values and `PUT /domains/{zone}/records/{name}/TXT` TTL 300; empty remaining set is `DELETE`

Credentials:

- `apiToken` — Gandi personal access token (preferred). Required unless API key is set
- `apiKey` — deprecated Gandi API key. Used only when the token is blank
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
