# ACMECertManager DNS-01 Plugins

Downloadable DNS-01 plugins for [ACMECertManager](https://github.com/caveman8080/ACMECertManager).

ACMECertManager loads provider DLLs from `plugins/` next to `acm.exe`. This repo ships **one zip per plugin** so you only download the provider you use.

## Install (download and drop)

1. Install [ACMECertManager](https://github.com/caveman8080/ACMECertManager/releases).
2. Open this repo's [v1 (Contract 1 plugins) release](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1) and download `<PluginName>.zip` for the plugin you want.
3. Extract the plugin DLL into `ACMECertManager/plugins/` (the folder beside `acm.exe`).
4. Restart ACMECertManager.
5. Issue a certificate with **DNS-01 (plugin)** and select the provider.

Do not copy `acm.exe` or other host files into `plugins/`. Each release zip contains only that plugin's DLL.

## Plugins

- [Hurricane Electric DDNS](docs/hurricane-electric.md)
- [Cloudflare](docs/cloudflare.md)
- [DuckDNS](docs/duckdns.md)
- [Porkbun](docs/porkbun.md)
- [DigitalOcean](docs/digitalocean.md)
- [Hetzner DNS](docs/hetzner.md)
- [GoDaddy](docs/godaddy.md)
- [Namecheap](docs/namecheap.md)
- [deSEC](docs/desec.md)
- [Dynu](docs/dynu.md)
- [Gandi LiveDNS](docs/gandi.md)
- [Linode](docs/linode.md)
- [Vultr](docs/vultr.md)
- [DNSimple](docs/dnsimple.md)
- [LuaDNS](docs/luadns.md)
- [Bunny.net DNS](docs/bunny.md)
- [ClouDNS](docs/cloudns.md)
- [OVH](docs/ovh.md)
- [Name.com](docs/namecom.md)
- [DNS Made Easy](docs/dns-made-easy.md)
- [Scaleway](docs/scaleway.md)
- [IONOS](docs/ionos.md)
- [Infomaniak](docs/infomaniak.md)
- [NS1](docs/ns1.md)
- [DreamHost](docs/dreamhost.md)
- [EasyDNS](docs/easydns.md)
- [Mythic Beasts](docs/mythic-beasts.md)
- [netcup](docs/netcup.md)
- [INWX](docs/inwx.md)
- [NameSilo](docs/namesilo.md)
- [Loopia](docs/loopia.md)
- [Selectel](docs/selectel.md)

These plugins talk to each provider over HTTP. AWS Route53, Azure DNS, and Google Cloud DNS are out of scope (they need official SDKs).

Every plugin exposes optional `propagationSeconds` (default 30). Credentials are stored by the host app in plaintext (`storage/dns-secrets.json`).

Missing a DNS provider? Open a [plugin request](https://github.com/caveman8080/ACMECertManager-DnsPlugins/issues/new?template=plugin-request.yml) issue. See [CONTRIBUTING.md](CONTRIBUTING.md).

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

Minimum SDK/runtime: .NET 10 (`net10.0-windows`). After a Release build, copy each `src/<Name>DnsPlugin/bin/Release/net10.0-windows/<Name>DnsPlugin.dll` into `plugins/`. Do not copy `acm.exe`.

## Releases

Plugins ship from a single floating GitHub Release tagged **[v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1)** ("Contract 1 plugins"). `v1` is the **IDnsValidationPlugin contract**, not a catalog version. There is no `v1.2.3` tag per plugin update.

Merging changes under `src/` (or this release workflow) to `main` rebuilds every plugin and updates that release in place. Each plugin is one zip: `<PluginName>.zip`, overwritten on each run.

Each zip contains only that plugin's DLL. Download `<PluginName>.zip` from the `v1` release, drop the DLL in `plugins/` next to `acm.exe`, and restart.

Do not push a SemVer tag to ship a plugin. Users download `<PluginName>.zip` from the `v1` release only. A `v2` release is only minted if the host interface breaks.

## License

GPL v3, same as [ACMECertManager](https://github.com/caveman8080/ACMECertManager). See [LICENSE](LICENSE).
