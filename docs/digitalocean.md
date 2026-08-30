# DigitalOcean

In-app name: **DigitalOcean**  
Release zip: `DigitalOceanDnsPlugin-vMAJOR.MINOR.PATCH.zip`

Follows `acme.sh` `dns_dgon.sh` against `https://api.digitalocean.com/v2`:

- Authenticate with `Authorization: Bearer`
- Detect the zone with `GET /domains/{name}`
- Present: `POST /domains/{zone}/records` TXT TTL 120
- Cleanup: list records (including extra pages) and `DELETE` the matching TXT

Credentials:

- `apiToken` — DigitalOcean personal access token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
