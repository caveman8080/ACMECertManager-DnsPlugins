# Porkbun

In-app name: **Porkbun**  
Release zip: `PorkbunDnsPlugin-vMAJOR.MINOR.PATCH.zip`

Follows `acme.sh` `dns_porkbun.sh` against `https://api.porkbun.com/api/json/v3`:

- Auth fields `apikey` and `secretapikey` on every JSON POST
- Detect the zone with `dns/retrieve/{domain}`
- Present: `dns/create/{domain}` TXT TTL 120
- Cleanup: match the TXT in the retrieve list, then `dns/delete/{domain}/{id}`

Credentials:

- `apiKey` — Porkbun API key (required)
- `apiSecret` — Porkbun secret API key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
