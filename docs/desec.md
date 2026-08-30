# deSEC

In-app name: **deSEC**  
Release zip: `DesecDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_desec.sh` against `https://desec.io/api/v1/domains`:

- Authenticate with `Authorization: Token`
- Detect the zone from `GET /domains/`
- Present/cleanup: `PUT /domains/{zone}/rrsets/` with the merged TXT RRset (TTL 3600)

Credentials:

- `apiToken` — deSEC API token (`DEDYN_TOKEN`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
