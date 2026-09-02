# DreamHost

In-app name: **DreamHost**  
Release zip: `DreamHostDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_dreamhost.sh` against `https://api.dreamhost.com/`:

- Authenticate with `key` on the query string (`format=json`)
- Present: `GET` `cmd=dns-add_record` TXT (`record_already_exists` is OK)
- Cleanup: `GET` `cmd=dns-remove_record` TXT (`no_record` / `no_such_record` is OK)

Credentials:

- `apiKey` — DreamHost API key (`DH_API_KEY`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

The key needs `dns-add_record` and `dns-remove_record`.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
