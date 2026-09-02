# Scaleway

In-app name: **Scaleway**  
Release zip: `ScalewayDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_scaleway.sh` against `https://api.scaleway.com/domain/v2beta1`:

- Authenticate with `x-auth-token`
- Detect the zone by probing `GET /dns-zones/{name}/records`
- Present: `PATCH /dns-zones/{zone}/records` add TXT TTL 60 if that name/value is not already there
- Cleanup: `PATCH` delete by `id_fields` (name, data, type TXT)

Credentials:

- `apiToken` — Scaleway API token (`SCALEWAY_API_TOKEN`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
