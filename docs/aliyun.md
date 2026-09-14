# Aliyun (Alibaba Cloud DNS)

In-app name: **Aliyun (Alibaba Cloud DNS)**  
Release zip: `AliyunDnsPlugin.zip` ([v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1))

Follows `acme.sh` `dns_ali.sh` against the Alibaba Cloud DNS RPC API `https://alidns.aliyuncs.com/`:

- Authenticate with AccessKey ID + HMAC-SHA1 query signature (`SignatureMethod=HMAC-SHA1`, key is `{secret}&`)
- Detect the zone with `Action=DescribeDomainRecords`
- Present: `Action=AddDomainRecord` Type TXT
- Cleanup: `DescribeDomainRecords` with `RRKeyWord` / `TypeKeyWord=TXT`, then `Action=DeleteDomainRecord`

No official SDK is used. Unicode names are converted to punycode before signing.

Credentials:

- `accessKeyId` — Aliyun AccessKey ID (`Ali_Key`) (required)
- `accessKeySecret` — Aliyun AccessKey secret (`Ali_Secret`) (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

Create a RAM user with `alidns:AddDomainRecord`, `alidns:DeleteDomainRecord`, and `alidns:DescribeDomainRecords`.

Install: download the zip, drop the DLL in `plugins/` next to `acm.exe`, and restart. See the [README](../README.md).
