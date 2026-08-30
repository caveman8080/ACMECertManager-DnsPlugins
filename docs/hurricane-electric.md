# Hurricane Electric DDNS

In-app name: **Hurricane Electric - DDNS**  
Release zip: `HurricaneElectricDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Ported from the ACMECertManager sample (`samples/HurricaneElectricDnsPlugin`). It follows the same high-level flow as `acme.sh` `dns_he_ddns.sh`:

- Update TXT through `https://dyn.dns.he.net/nic/update`
- Send `hostname`, `password` (DDNS key), and `txt`
- Treat `good` and `nochg` responses as success
- Cleanup is a no-op because HE DDNS updates the same record target

Credentials (entered in ACMECertManager):

- `ddnsKey` — Hurricane Electric DDNS key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

This plugin targets HE DDNS, not the dns.he.net zone-edit form API.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
