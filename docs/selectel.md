# Selectel

In-app name: **Selectel**  
Release zip: `SelectelDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_selectel.sh` against the Selectel DNS HTTP API:

- **v2 (current):** Keystone token from `POST https://cloud.api.selcloud.ru/identity/v3/auth/tokens`, then `https://api.selectel.ru/domains/v2` with `X-Auth-Token`
- **v1 (legacy):** `https://api.selectel.ru/domains/v1` with `X-Token`
- Detect the zone from `GET /zones` (v2) or `GET /` (v1)
- Present: create a TXT rrset/record if that name/value is not already there (HTTP 2xx)
- Cleanup: drop the matching TXT value (PATCH remaining v2 answers, or DELETE)

Credentials (v2, preferred):

- `loginId` — account ID (`SL_Login_ID`)
- `projectName` — project name (`SL_Project_Name`)
- `loginName` — service user name (`SL_Login_Name`)
- `password` — service user password (`SL_Pswd`)

Credentials (v1, if v2 fields are empty):

- `apiKey` — legacy API key (`SL_Key`)
- `propagationSeconds` — optional wait before ACME validation (default 30)

v2 needs a service user with DNS access in the project. HTTP 401/403 are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
