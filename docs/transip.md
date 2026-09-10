# TransIP

In-app name: **TransIP**  
Release zip: `TransIpDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_transip.sh` against the TransIP REST API `https://api.transip.nl/v6`:

- Authenticate with `Authorization: Bearer` (control-panel access token, or a JWT minted from login + RSA private key)
- Detect the zone with `GET /domains/{candidate}/dns`
- Present: `POST /domains/{zone}/dns` TXT expire 60 if that name/value is not already there (HTTP 2xx)
- Cleanup: `DELETE /domains/{zone}/dns` with the matching `dnsEntry` body

Credentials (use one of):

- `accessToken` — JWT from the [TransIP API page](https://www.transip.nl/cp/account/api) (simplest; tokens expire, max 1 month)
- **or** `login` + `privateKey` — account name and RSA private key PEM from a Key Pair on that same page; the plugin `POST`s `/auth` with a SHA-512 signature to mint a short-lived token
- `globalKey` — optional when minting (`true`/`false`, default `true`). `true` allows the minted token from any IP; `false` requires a whitelisted IP
- `propagationSeconds` — optional wait before ACME validation (default 30)

Paste the PEM as-is (including `BEGIN`/`END` lines). If you store it as a single line, use `\n` for newlines.

HTTP 401/403 are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
