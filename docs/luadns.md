# LuaDNS

In-app name: **LuaDNS**  
Release zip: `LuaDnsDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_lua.sh` against `https://api.luadns.com/v1`:

- Authenticate with HTTP Basic (`email:apiKey`)
- Detect the zone from `GET /zones`
- Present: `POST /zones/{id}/records` TXT TTL 120 using the FQDN with a trailing dot
- Cleanup: list records and `DELETE /zones/{id}/records/{recordId}`

Credentials:

- `email` — LuaDNS account email (required)
- `apiKey` — LuaDNS API key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
