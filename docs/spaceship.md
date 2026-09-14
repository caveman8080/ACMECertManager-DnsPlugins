# Spaceship

In-app name: **Spaceship**  
Release zip: `SpaceshipDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_spaceship.sh` against `https://spaceship.dev/api/v1`:

- Authenticate with `X-API-Key` and `X-API-Secret`
- Detect the zone with `GET /dns/records/{domain}?take=1&skip=0`
- Present: `PUT /dns/records/{zone}` TXT TTL 600 (`force: true`)
- Cleanup: `DELETE /dns/records/{zone}` matching the TXT name and value (HTTP 204)

Credentials:

- `apiKey` — Spaceship API key (`SPACESHIP_API_KEY`) (required)
- `apiSecret` — Spaceship API secret (`SPACESHIP_API_SECRET`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create keys at [Spaceship](https://www.spaceship.com/) with `dnsrecords:read` and `dnsrecords:write`. API docs: [docs.spaceship.dev](https://docs.spaceship.dev/).

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
