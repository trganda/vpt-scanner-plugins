# VPT Scanner Plugins

Public runtime scanner plugins and the shared go-plugin gRPC SDK for VPT.

## Modules

- `sdk`: host/plugin protocol and HashiCorp go-plugin wrappers.
- `portscan`: naabu-backed TCP port scanner (`portscan`).
- `subfinder`: subfinder-backed enumeration (`subdomain`).
- `httpprobe`: httpx-backed HTTP probing (`httpprobe`).
- `nuclei`: nuclei-backed vulnerability scanning (`vuln`).

## Releases

Each plugin is released independently using `plugin-<capability>-vX.Y.Z` tags.
GitHub Actions publishes Linux amd64/arm64 binaries and SLSA provenance.

```bash
make test
make build
```
