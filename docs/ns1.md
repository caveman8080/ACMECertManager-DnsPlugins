# NS1

In-app name: **NS1**  
Release zip: `Ns1DnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_nsone.sh` against `https://api.nsone.net/v1`:

- Authenticate with `X-NSONE-Key`
- Detect the zone from `GET /zones`
- Present: `PUT /zones/{zone}/{fqdn}/TXT` when the record is new, or `POST` to add a TXT answer TTL 0 if that value is not already there
- Cleanup: drop the matching TXT answer (`POST` remaining answers, or `DELETE` the record when none remain)

Credentials:

- `apiKey` — NS1 API key (`NS1_Key`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
