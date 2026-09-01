# OVH

In-app name: **OVH**  
Release zip: `OvhDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_ovh.sh` against `https://eu.api.ovh.com/1.0` (or the selected endpoint):

- Authenticate with `X-Ovh-Application`, `X-Ovh-Consumer`, `X-Ovh-Timestamp`, and `X-Ovh-Signature` (`$1$` + SHA1 of secret+consumer+method+url+body+timestamp)
- Detect the zone with `GET /domain/zone/{name}`
- Present: `POST /domain/zone/{zone}/record` TXT TTL 60, then `POST /domain/zone/{zone}/refresh`
- Cleanup: list TXT ids, `DELETE /domain/zone/{zone}/record/{id}`, then refresh

Credentials:

- `applicationKey` — OVH application key (`OVH_AK`) (required)
- `applicationSecret` — OVH application secret (`OVH_AS`) (required)
- `consumerKey` — OVH consumer key (`OVH_CK`) (required)
- `endpoint` — optional; default `ovh-eu` (`ovh-us`, `ovh-ca`, `kimsufi-eu`, `kimsufi-ca`, `soyoustart-eu`, `soyoustart-ca`, or a full API URL)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create keys at the OVH token page for your region (for example [eu.api.ovh.com/createToken](https://eu.api.ovh.com/createToken/)) with access to `/domain/zone/*` record GET/POST/PUT/DELETE and `/domain/zone/*/refresh`.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
