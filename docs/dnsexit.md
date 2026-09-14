# DNSExit

In-app name: **DNSExit**  
Release zip: `DnsExitDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_dnsexit.sh` against `https://api.dnsexit.com/dns/`:

- Authenticate with the `apikey` HTTP header
- Detect the zone by posting the add/delete payload at each domain level until the API returns `"code":0` (DNSExit has no zone-list call)
- Present: JSON `add` TXT with `ttl` 1 minute and `overwrite: false`
- Cleanup: JSON `delete` for that TXT name and content

Credentials:

- `apiKey` — DNSExit API key (`DNSEXIT_API_KEY`) (required). Create it under Settings → DNS API Key
- `propagationSeconds` — optional wait before ACME validation (default 30)

DNSExit documents TTL in minutes. **Cleanup sends the TXT value; if the provider still deletes every TXT at that name, other values on the same host would be removed.**

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
