# INWX

In-app name: **INWX**  
Release zip: `InwxDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_inwx.sh` against the INWX DomRobot JSON-RPC endpoint `https://api.domrobot.com/jsonrpc/` (same methods as the XML-RPC API):

- Authenticate with `account.login` (`user` / `pass`); optional TOTP via `account.unlock` when Mobile TAN is enabled
- Detect the zone from `nameserver.list`
- Present: `nameserver.createRecord` TXT if that name/value is not already there
- Cleanup: `nameserver.info`, then `nameserver.deleteRecord`

Credentials:

- `username` — INWX username (`INWX_User`) (required)
- `password` — INWX password (`INWX_Password`) (required)
- `sharedSecret` — optional TOTP shared secret (`INWX_Shared_Secret`)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Login / `2200` failures are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
