# Name.com

In-app name: **Name.com**  
Release zip: `NameComDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_namecom.sh` against `https://api.name.com/v4`:

- Authenticate with HTTP Basic (`username:token`); `GET /hello` checks the token (whitelist this machine's IP in the Name.com API settings)
- Detect the zone with `GET /domains/{name}` (not the paginated domain list)
- Present: `POST /domains/{zone}/records` TXT TTL 300 if that name/value is not already there
- Cleanup: list records and `DELETE /domains/{zone}/records/{recordId}`

Credentials:

- `username` — Name.com account username (required)
- `apiToken` — Name.com API token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
