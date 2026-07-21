# Writing a VPT scanner plugin

This guide describes the public SDK used by the runtime plugins in this
repository. A plugin is a small Go module that implements `sdk.Scanner`, is
served through HashiCorp go-plugin, and returns an opaque JSON result to the
host.

## Module setup

Keep the plugin in its own Go module and import the public SDK module:

```go
module example.com/acme/example-scanner

go 1.26.3

require github.com/trganda/vpt-scanner-plugins/sdk v0.2.1
```

Use the released SDK version selected for the plugin release. Do not copy the
SDK or generated protobuf package into the plugin module. The SDK's `Target`
contains the target host and string parameters; `Result.RawJSON` is the
tool-specific JSON payload consumed by the host.

## Implementing `sdk.Scanner`

`Scanner` requires capability discovery, both execution methods, and the
pre-scan hook. `Execute` is retained for compatibility; its normal
implementation delegates to `ExecuteStream` with no event sink.

The following is a complete minimal scanner implementation. It compiles as a
`package main` in a module that requires the SDK:

```go
package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

type scanner struct{}

func (scanner) Capability(context.Context) (string, error) {
	return "example", nil
}

func (s scanner) Execute(ctx context.Context, target sdk.Target) (sdk.Result, error) {
	return s.ExecuteStream(ctx, target, nil)
}

func (scanner) ExecuteStream(ctx context.Context, target sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	if target.Host == "" {
		return sdk.Result{}, errors.New("example: empty target host")
	}

	sequence := int64(0)
	emit := func(level, typ, message string, fields map[string]string) error {
		if sink == nil {
			return nil
		}
		sequence++
		event := sdk.NewEvent(level, typ, message, fields)
		event.Sequence = sequence
		return sink(event)
	}

	if err := emit("info", "scan_started", "example scan started", nil); err != nil {
		return sdk.Result{}, err
	}

	// Run the tool here. Respect ctx.Done() in long-running tool operations.
	resultPayload, err := json.Marshal(map[string]any{
		"host":  target.Host,
		"count": 0,
	})
	if err != nil {
		_ = emit("error", "scan_failed", "example scan failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	if err := ctx.Err(); err != nil {
		_ = emit("error", "scan_failed", "example scan failed", map[string]string{"reason": "canceled"})
		return sdk.Result{}, err
	}
	if err := emit("info", "scan_completed", "example scan completed", map[string]string{"count": "0"}); err != nil {
		return sdk.Result{}, err
	}

	return sdk.Result{Capability: "example", RawJSON: resultPayload}, nil
}

func (scanner) Prepare(context.Context, string) error { return nil }

var _ sdk.Scanner = scanner{}
```

The production tools use the same shape while delegating the work to their
tool-specific scanner ports. `Prepare` is a no-op unless the tool needs a
pre-scan operation, such as synchronizing nuclei templates.

## Serving the plugin

The executable's `main` constructs the scanner and calls `sdk.Serve`:

```go
package main

import "github.com/trganda/vpt-scanner-plugins/sdk"

func main() {
	sdk.Serve(scanner{})
}
```

`Serve` installs the SDK's go-plugin handshake, plugin map, and gRPC server.
The handshake uses magic cookie `VPT_SCAN_PLUGIN=vpt-scanner-plugin` and
`ProtocolVersion: 1`. Plugin logging must go to **stderr** because go-plugin
uses stdout for its startup handshake.

## Execute and additive `ExecuteStream`

`Execute` remains the unary compatibility operation and returns only the
terminal `sdk.Result`. New hosts should call:

```go
result, err := scanner.ExecuteStream(ctx, target, func(event sdk.Event) error {
	// Forward or record the event, then return nil to continue.
	return nil
})
```

The streaming RPC sends zero or more progress events and then exactly one
terminal result. The terminal result is not delivered to the sink; it is the
returned `sdk.Result`. A plugin error (including an event-sink error) ends the
operation without a terminal result and is returned as `err`.

`ExecuteStream` is additive to the existing gRPC service. It does not change
the handshake version, so rolling deployments continue to use protocol
version 1. A host that receives an unimplemented-stream error from an older
plugin should fall back to `Execute`; the fallback has result compatibility but
does not provide progress events. The next patch release for this API rollout
is `v0.2.1`.

## Safe structured events

An `sdk.Event` contains:

- `Sequence`: a plugin-local, per-call sequence number;
- `Level`: normally `info`, `warn`, or `error`;
- `Type`: a stable machine-readable name such as `scan_started`;
- `Message`: a short human-readable description;
- `Fields`: bounded string key/value metadata; and
- `OccurredAt`: a timestamp supplied by `sdk.NewEvent` (UTC).

Use stable event types and small aggregate values, for example:

```go
event := sdk.NewEvent("info", "scan_completed", "scan completed",
	map[string]string{"count": "12"})
event.Sequence = 2
if err := sink(event); err != nil {
	return err
}
```

Never emit stdout/stderr, credentials, auth tokens, request parameters, raw
request or response bodies, URLs containing secrets, or unbounded tool output.
Prefer generic failure reasons such as `scanner_error`, and keep fields to
small counts, modes, or bounded status values. The SDK bridge additionally
limits event fields to 16 entries and 256 bytes per key/value before sending
them over gRPC.
