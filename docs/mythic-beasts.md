# Mythic Beasts

In-app name: **Mythic Beasts**  
Release zip: `MythicBeastsDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_mythic_beasts.sh` against `https://api.mythic-beasts.com/dns/v2/zones`:

- Authenticate with OAuth2 client credentials (`POST https://auth.mythic-beasts.com/login`, then `Authorization: Bearer`)
- Detect the zone from `GET /zones` or by probing `GET /{zone}/records`
- Present: `POST /{zone}/records/{host}/TXT` form `data={txt}` if that name/value is not already there
- Cleanup: `DELETE /{zone}/records/{host}/TXT?data={txt}`

Credentials:

- `apiKey` — Mythic Beasts API key (`MB_AK`) (required)
- `apiSecret` — Mythic Beasts API secret (`MB_AS`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create keys in the [API Keys](https://www.mythic-beasts.com/customer/api-users) control panel. Restricted keys need permit for `_acme-challenge` TXT.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
