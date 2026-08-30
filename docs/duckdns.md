# DuckDNS

In-app name: **DuckDNS**  
Release zip: `DuckDnsDnsPlugin-vMAJOR.MINOR.PATCH.zip`

Follows `acme.sh` `dns_duckdns.sh` against `https://www.duckdns.org/update`:

- Present: `GET` with `domains`, `token`, and `txt`
- Cleanup: `GET` with `txt=` and `clear=true` (DuckDNS has one TXT slot per domain)
- The DuckDNS subdomain is taken from the record name (`*.duckdns.org`)

Credentials:

- `token` — DuckDNS account token (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
