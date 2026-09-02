# DNS Made Easy

In-app name: **DNS Made Easy**  
Release zip: `DnsMadeEasyDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_me.sh` against `https://api.dnsmadeeasy.com/V2.0/dns/managed`:

- Authenticate with `x-dnsme-apiKey`, `x-dnsme-requestDate` (GMT RFC 1123), and `x-dnsme-hmac` (HMAC-SHA1 of the date)
- Detect the zone with `GET /name?domainname={zone}`
- Present: `POST /{zoneId}/records/` TXT TTL 120 (`gtdLocation` DEFAULT) if that name/value is not already there
- Cleanup: list TXT records and `DELETE /{zoneId}/records/{recordId}`

Credentials:

- `apiKey` — DNS Made Easy API key (`ME_Key`) (required)
- `apiSecret` — DNS Made Easy secret (`ME_Secret`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
