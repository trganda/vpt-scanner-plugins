package sdk_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	goplugin "github.com/hashicorp/go-plugin"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// stubScanner is a Scanner implementation served over the in-memory gRPC
// harness so we can assert the proto bridge round-trips every field. Plain
// stdlib testing keeps this small module free of ginkgo/gomega.
type stubScanner struct {
	gotTarget sdk.Target
	gotToken  string
}

func (s *stubScanner) Capability(context.Context) (string, error) { return "portscan", nil }

func (s *stubScanner) Prepare(_ context.Context, token string) error {
	s.gotToken = token
	return nil
}

func (s *stubScanner) Execute(_ context.Context, t sdk.Target) (sdk.Result, error) {
	return s.ExecuteStream(context.Background(), t, nil)
}

func (s *stubScanner) ExecuteStream(_ context.Context, t sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	s.gotTarget = t
	if sink != nil {
		if err := sink(sdk.Event{Sequence: 1, Level: "info", Type: "scan_started", Message: "started", OccurredAt: time.Unix(1, 0).UTC()}); err != nil {
			return sdk.Result{}, err
		}
	}
	raw, _ := json.Marshal(map[string]any{"host": t.Host, "echo": t.Params["k"]})
	return sdk.Result{
		Capability:         "portscan",
		RawJSON:            raw,
		StartedAtUnixNano:  1000,
		FinishedAtUnixNano: 2000,
	}, nil
}

func TestGRPCRoundTrip(t *testing.T) {
	stub := &stubScanner{}
	client, _ := goplugin.TestPluginGRPCConn(t, false, sdk.PluginMap(stub))
	defer client.Close()

	raw, err := client.Dispense(sdk.PluginName)
	if err != nil {
		t.Fatalf("dispense: %v", err)
	}
	sc, ok := raw.(sdk.Scanner)
	if !ok {
		t.Fatalf("dispensed %T, want sdk.Scanner", raw)
	}
	ctx := context.Background()

	cap, err := sc.Capability(ctx)
	if err != nil || cap != "portscan" {
		t.Fatalf("Capability = %q, %v; want portscan, nil", cap, err)
	}

	res, err := sc.Execute(ctx, sdk.Target{Host: "example.com", Params: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stub.gotTarget.Host != "example.com" || stub.gotTarget.Params["k"] != "v" {
		t.Fatalf("server saw target %+v; host/params not round-tripped", stub.gotTarget)
	}
	if res.Capability != "portscan" || res.StartedAtUnixNano != 1000 || res.FinishedAtUnixNano != 2000 {
		t.Fatalf("result envelope not round-tripped: %+v", res)
	}
	var decoded map[string]any
	if err := json.Unmarshal(res.RawJSON, &decoded); err != nil {
		t.Fatalf("raw_json not valid JSON: %v", err)
	}
	if decoded["host"] != "example.com" || decoded["echo"] != "v" {
		t.Fatalf("raw_json payload not round-tripped: %v", decoded)
	}
	var events []sdk.Event
	res, err = sc.ExecuteStream(ctx, sdk.Target{Host: "example.com"}, func(event sdk.Event) error { events = append(events, event); return nil })
	if err != nil || len(events) != 1 || events[0].Type != "scan_started" || res.Capability != "portscan" {
		t.Fatalf("ExecuteStream = %+v, events=%+v, err=%v", res, events, err)
	}

	if err := sc.Prepare(ctx, "tok-123"); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if stub.gotToken != "tok-123" {
		t.Fatalf("Prepare token = %q; want tok-123", stub.gotToken)
	}
}
