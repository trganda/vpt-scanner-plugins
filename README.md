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
additive gRPC method and therefore does not require a handshake bump.
`ScanPlugin.ExecuteStream` is the canonical scan operation: it delivers
structured, bounded progress events followed by one terminal result. Events
contain a per-call sequence, level, type, safe message, string fields, and UTC
timestamp; plugin stdout/stderr, credentials, parameters, and request/response
bodies are never captured. `Execute` remains available as a compatibility
operation.

Capability contracts are additive to that protocol. The dependency-free
`sdk/contract` package validates and canonicalizes versioned manifests, governed
parameters, and typed orchestration outputs. Contract-aware plugins use
`ServeWithManifest`; existing `Scanner` implementations and plugins using
`Serve` remain source compatible and continue to execute legacy requests with
their historical permissive parameters and Raw-only responses. `Describe` and
contract-bearing execution are optional interfaces exposed by the SDK client.
The `--print-manifest` helper emits the same canonical bytes returned by
`Describe` without initializing a scanner tool.

Plugins may advertise compatible canonical manifests with
`ServeWithManifests`; contract requests select and echo an exact contract
digest. Optional `BatchScanner` implementations use the additive batch stream
without changing the `Scanner` source contract. Release tooling also emits
`*_compatible_contracts.json` and `*_runtime.json` assets.

## Releases

Plugins can be released independently using `plugin-<capability>-vX.Y.Z` tags,
or together using a `vX.Y.Z` tag. GitHub Actions publishes Linux amd64/arm64
binaries, canonical contract manifests, and SLSA provenance. The initial
contract-aware rollout uses the four per-capability `v0.3.0` tags because the
backend catalog currently validates capability-scoped source tags.

```bash
make generate
make test
make build
```
