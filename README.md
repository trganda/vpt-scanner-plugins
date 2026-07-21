# VPT Scanner Plugins

Public runtime scanner plugins and the shared go-plugin gRPC SDK for VPT.

## Modules

- `sdk`: host/plugin protocol and HashiCorp go-plugin wrappers.
- `portscan`: naabu-backed TCP port scanner (`portscan`).
- `subfinder`: subfinder-backed enumeration (`subdomain`).
- `httpprobe`: httpx-backed HTTP probing (`httpprobe`).
- `nuclei`: nuclei-backed vulnerability scanning (`vuln`).

## Protocol

The SDK retains go-plugin handshake `ProtocolVersion: 1`: `ExecuteStream` is an
additive gRPC method and therefore does not require a handshake bump. The
next patch release for this rollout is `v0.2.1`. `ScanPlugin.ExecuteStream` is
the canonical scan operation: it delivers
structured, bounded progress events followed by one terminal result. Events
contain a per-call sequence, level, type, safe message, string fields, and UTC
timestamp; plugin stdout/stderr, credentials, parameters, and request/response
bodies are never captured. `Execute` remains available as a compatibility
operation.

## Releases

Plugins can be released independently using `plugin-<capability>-vX.Y.Z` tags,
or together using a `vX.Y.Z` tag. GitHub Actions publishes Linux amd64/arm64
binaries and SLSA provenance.

```bash
make test
make build
```
