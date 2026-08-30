# DNSimple

In-app name: **DNSimple**  
Release zip: `DnsimpleDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_dnsimple.sh` against `https://api.dnsimple.com/v2`:

- Authenticate with `Authorization: Bearer`
- Resolve the account from `GET /whoami` (or `GET /accounts` for a user token); set Account ID if the token can see more than one account
- Detect the zone with `GET /{account}/zones/{name}`
- Present: `POST /{account}/zones/{zone}/records` TXT TTL 120
- Cleanup: list records and `DELETE` the matching TXT

Credentials:

- `oauthToken` — DNSimple account access token (required)
- `accountId` — optional; required when the token can access multiple accounts
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
