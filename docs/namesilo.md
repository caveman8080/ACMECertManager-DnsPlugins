# NameSilo

In-app name: **NameSilo**  
Release zip: `NameSiloDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_namesilo.sh` against `https://www.namesilo.com/api` (`version=1`, `type=json`):

- Authenticate with `key` on the query string
- Detect the zone from `listDomains` (reply code `300`)
- Present: `dnsAddRecord` TXT (`rrhost` + `rrvalue`) if that name/value is not already there
- Cleanup: `dnsListRecords`, then `dnsDeleteRecord` (`rrid`)

Credentials:

- `apiKey` — NameSilo API key (`Namesilo_Key`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create a key in the NameSilo API Manager. Reply codes `110`–`115` are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
