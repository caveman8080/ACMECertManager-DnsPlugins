# netcup

In-app name: **netcup**  
Release zip: `NetcupDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_netcup.sh` against `https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON`:

- Authenticate with `login` (`customernumber`, `apikey`, `apipassword`) and use `apisessionid`
- Detect the zone by probing `infoDnsRecords` (statuscode `5028` = not this zone)
- Present: `updateDnsRecords` TXT if that name/value is not already there
- Cleanup: `infoDnsRecords`, then `updateDnsRecords` with `deleterecord` for the matching record id

Credentials:

- `customerNumber` — netcup customer number (`NC_CID`) (required)
- `apiKey` — netcup API key (`NC_Apikey`) (required)
- `apiPassword` — netcup API password (`NC_Apipw`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create the key in the netcup CCP (API access). Login failures are reported as authentication errors, not as a missing zone.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
