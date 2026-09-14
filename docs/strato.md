# Strato

In-app name: **Strato**  
Release zip: `StratoDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Strato has no public DNS REST API. This plugin follows the same CustomerService portal endpoints used by `strato-certbot` / the unmerged acme.sh `dns_strato.sh` work:

- `https://www.strato.de/apps/CustomerService` (override with `portalUrl` for `.nl` / `.uk`)
- Login with customer number + password (`action_customer_login.x`); optional TOTP (`totpSecret`, `totpDeviceName`)
- Session cookie + `sessionID` query parameter
- List TXT/CNAME: `node=ManageDomains` and `action_show_txt_records`
- Present/cleanup: POST `action_change_txt_records` with the full prefix/type/value list

The portal HTML is not a stable contract. If Strato changes the login or DNS forms, this plugin will need an update.

Credentials:

- `username` — STRATO customer number or login (required)
- `password` — STRATO customer password (required)
- `portalUrl` — optional; default `https://www.strato.de/apps/CustomerService`
- `totpSecret` — optional Base32 TOTP secret when two-factor is enabled
- `totpDeviceName` — optional 2FA device name shown in the portal
- `propagationSeconds` — optional wait before ACME validation (default 30)

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
