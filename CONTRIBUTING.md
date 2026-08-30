# Contributing

This archive ships downloadable DNS-01 plugins for [ACMECertManager](https://github.com/caveman8080/ACMECertManager). Users request providers here; maintainers add them under `src/`.

## Request a plugin (users)

1. Open a **Plugin request** issue with the [plugin request form](https://github.com/caveman8080/ACMECertManager-DnsPlugins/issues/new?template=plugin-request.yml).
2. Fill in provider name, why you need it (include the acme.sh dnsapi name if you use one), API docs URL, required credentials, and any extra notes.
3. Do not paste live API keys, tokens, or passwords.

The form prefixes the title with `[plugin] `, applies the `plugin-request` label, and assigns `@caveman8080`. A maintainer reviews whether the provider fits **contract 1** and the HttpClient-only rule. You do not need to open a pull request.

## Add a plugin (maintainers)

1. Create a sibling project `src/<Name>DnsPlugin/` whose folder name matches the `.csproj` (CI packs `src/<Name>DnsPlugin/<Name>DnsPlugin.csproj`).
2. Implement **contract 1** (`IDnsValidationPlugin` on ACMECertManager `main`). `ProjectReference` `ACMECertManager/src/ACMECertManager.csproj`. Do not copy or redefine the interface in the plugin assembly.
3. Call the provider with `HttpClient` only. Add a NuGet package only after a maintainer approves that SDK. Route53, Azure DNS, and similar SDK-only providers stay out of scope until then.
4. Add the project to `ACMECertManager.DnsPlugins.sln`, add a page under `docs/`, and link it from the plugin list in [README.md](README.md).
5. Build Release, then drop **only** that plugin DLL into ACMECertManager `plugins/` (the folder beside `acm.exe`). Do not copy `acm.exe` or other host files.
6. Do not push a SemVer git tag (`v1.2.3`) to ship. After merge to `main`, GitHub Actions updates the floating **[v1](https://github.com/caveman8080/ACMECertManager-DnsPlugins/releases/tag/v1)** release in place, overwriting each `<PluginName>.zip`. Users download `<PluginName>.zip` from that release only. A `v2` release is only minted if the host interface breaks.

Contract 1 and the install path are documented in [README.md](README.md).
