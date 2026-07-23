# AGENTS.md

## Repository overview

This repository contains public VPT scanner plugins and their shared gRPC SDK.
It is a multi-module Go repository:

- `sdk`: host/plugin protocol and HashiCorp `go-plugin` wrappers.
- `portscan`: naabu-backed TCP port scanner (`portscan`).
- `subfinder`: subfinder-backed enumeration (`subdomain`).
- `httpprobe`: httpx-backed HTTP probing (`httpprobe`).
- `nuclei`: nuclei-backed vulnerability scanner (`vuln`).

## Development rules

- Treat each top-level module as an independent Go module. Run Go commands in
  the affected module with `GOWORK=off`.
- Use Go 1.26.3 and keep `go.mod` and `go.sum` changes scoped to required
  dependencies.
- Format changed Go files with `gofmt`.
- Prefer dependency injection and fakes for external scanner engines, following
  existing test seams.
- Do not commit binaries or other build artifacts from `bin/`.

## SDK and protocol changes

- Protobuf sources live in `sdk/proto/scan/v1`; regenerate generated code with
  `make generate` after changing protobuf definitions or Buf configuration.
- Preserve the go-plugin handshake `ProtocolVersion: 1`. `ExecuteStream` is an
  additive gRPC method; retain its compatibility semantics alongside `Execute`.
- `ExecuteStream` must emit bounded, structured progress events followed by one
  terminal result.
- Never include plugin stdout/stderr, credentials, scan parameters, or request
  or response bodies in progress events.

## Validation

Choose validation that matches the change:

```bash
# All modules
make test

# A focused module
(cd <module> && GOWORK=off go test -race ./...)

# Plugin binary changes
make build

# Protobuf or Buf configuration changes
make generate
```

For release-like builds, use:

```bash
(cd <module> && GOWORK=off CGO_ENABLED=0 go build -trimpath .)
```

Plugin releases target Linux amd64 and arm64. Capability-specific tags use
`plugin-<capability>-vX.Y.Z`; a `vX.Y.Z` tag releases all plugins.
