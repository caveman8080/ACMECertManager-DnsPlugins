# ACMECertManager DNS-01 Plugins

Downloadable DNS-01 plugins for [ACMECertManager](https://github.com/caveman8080/ACMECertManager).

ACMECertManager loads provider DLLs from `plugins/` next to `acm.exe`. This repo ships **one zip per plugin** so you only download the provider you use.

## Install (download and drop)

1. Install [ACMECertManager](https://github.com/caveman8080/ACMECertManager/releases).
2. Open this repo's [Releases](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases) and download the zip for the plugin you want.
3. Extract the plugin DLL into `ACMECertManager/plugins/` (the folder beside `acm.exe`).
4. Restart ACMECertManager.
5. Issue a certificate with **DNS-01 (plugin)** and select the provider.

Do not copy `acm.exe` or other host files into `plugins/`. Each release zip contains only that plugin's DLL.

## Plugins

| Plugin | Release zip | In-app name |
| --- | --- | --- |
| [Hurricane Electric DDNS](#hurricane-electric-ddns) | `HurricaneElectricDnsPlugin-vMAJOR.MINOR.PATCH.zip` | Hurricane Electric - DDNS |

Additional providers can be added later as sibling projects under `src/`. Cloudflare, Route53, Azure, and other SDK-based providers are out of scope here.

## Plugin contract

ACMECertManager discovers plugins with `typeof(IDnsValidationPlugin).IsAssignableFrom` on `*.dll` files in `plugins/`. That type lives in the **app assembly** (`src/DnsPlugins.cs`, namespace `ACMECertManager`). A second copy of the interface in a plugin assembly will not load.

**Contract 1** is the current ACMECertManager `main` interface:

```csharp
public interface IDnsValidationPlugin
{
    DnsPluginMetadata Metadata { get; }
    IReadOnlyList<DnsCredentialField> GetCredentialFields();
    Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken);
    Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken);
}
```

Related contract types (same assembly): `DnsPluginMetadata`, `DnsCredentialField`, `DnsChallengeRequest`.

Plugins in this repo **ProjectReference** `ACMECertManager/src/ACMECertManager.csproj`. They do not redefine `IDnsValidationPlugin`.

If the host interface changes in a breaking way, this archive will document a new contract version.

## Hurricane Electric DDNS

Ported from the ACMECertManager sample (`samples/HurricaneElectricDnsPlugin`). It follows the same high-level flow as `acme.sh` `dns_he_ddns.sh`:

- Update TXT through `https://dyn.dns.he.net/nic/update`
- Send `hostname`, `password` (DDNS key), and `txt`
- Treat `good` and `nochg` responses as success
- Cleanup is a no-op because HE DDNS updates the same record target

Credentials (entered in ACMECertManager):

- `ddnsKey` — Hurricane Electric DDNS key (required)
- `propagationSeconds` — optional wait before ACME validation (default 30)

This plugin targets HE DDNS, not the dns.he.net zone-edit form API. Credentials are stored by the host app in plaintext (`storage/dns-secrets.json`).

## Build from source

Plugins compile against the real `IDnsValidationPlugin` type in ACMECertManager. Clone the app next to this tree (or add it as a submodule) so `ACMECertManager/src/ACMECertManager.csproj` exists.

**Clone both** (app checkout inside this repo — same layout CI uses):

```powershell
git clone https://github.com/caveman8080/ACMECertManager-DnsPlugins.git
cd ACMECertManager-DnsPlugins
git clone https://github.com/caveman8080/ACMECertManager.git ACMECertManager
dotnet build ACMECertManager.DnsPlugins.sln -c Release
```

**Clone both as siblings**, then junction or symlink the app in:

```powershell
git clone https://github.com/caveman8080/ACMECertManager.git
git clone https://github.com/caveman8080/ACMECertManager-DnsPlugins.git
cd ACMECertManager-DnsPlugins
cmd /c mklink /J ACMECertManager ..\ACMECertManager
dotnet build ACMECertManager.DnsPlugins.sln -c Release
```

**Submodule** (optional; remove `/ACMECertManager/` from `.gitignore` first):

```powershell
git submodule add https://github.com/caveman8080/ACMECertManager.git ACMECertManager
dotnet build ACMECertManager.DnsPlugins.sln -c Release
```

Minimum SDK/runtime: .NET 10 (`net10.0-windows`). After a Release build, copy `src/HurricaneElectricDnsPlugin/bin/Release/net10.0-windows/HurricaneElectricDnsPlugin.dll` into `plugins/`. Do not copy `acm.exe`.

## Releases

Push a tag `vMAJOR.MINOR.PATCH` (for example `v1.0.0`). GitHub Actions builds each plugin and uploads one zip per plugin. The zip contains only that plugin's DLL.

## License

GPL v3, same as [ACMECertManager](https://github.com/caveman8080/ACMECertManager). See [LICENSE](LICENSE).
