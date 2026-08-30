# Namecheap

In-app name: **Namecheap**  
Release zip: `NamecheapDnsPlugin-vMAJOR.MINOR.PATCH.zip`

Follows `acme.sh` `dns_namecheap.sh` against `https://api.namecheap.com/xml.response`.

Namecheap `setHosts` **replaces the whole host list**. The plugin reads every existing host with `domains.dns.getHosts`, then writes the full list back with the challenge TXT added or removed.

Credentials:

- `apiUser` — Namecheap API user (required)
- `apiKey` — Namecheap API key (required)
- `clientIp` — IPv4 that Namecheap has allowlisted, or a URL that returns that IPv4. Optional; if blank the plugin fetches `https://api.ipify.org`
- `propagationSeconds` — optional wait before ACME validation (default 30)

Enable API access in the Namecheap account and allowlist the client IP.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
