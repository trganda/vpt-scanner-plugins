package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// fakeProber is a double for the prober port so these tests don't drag the
// httpx SDK or live network into the unit suite.
type fakeProber struct {
	probes   []ProbeResult
	err      error
	calls    int
	gotHost  string
	gotPorts string
	block    bool
}

func (f *fakeProber) Probe(ctx context.Context, host, ports string) ([]ProbeResult, error) {
	f.calls++
	f.gotHost = host
	f.gotPorts = ports
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.probes, f.err
}

func decodeRaw(t *testing.T, r sdk.Result) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.RawJSON, &m); err != nil {
		t.Fatalf("raw_json invalid: %v", err)
	}
	return m
}

func TestExecute_RawShape(t *testing.T) {
	fake := &fakeProber{probes: []ProbeResult{
		{URL: "https://example.com", Scheme: "https", StatusCode: 200, WebServer: "nginx"},
	}}
	s := newWithProber(fake, 0)

	res, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Capability != capability {
		t.Fatalf("capability = %q", res.Capability)
	}
	raw := decodeRaw(t, res)
	if raw["host"] != "example.com" {
		t.Fatalf("host = %v", raw["host"])
	}
	if raw["count"] != float64(1) {
		t.Fatalf("count = %v, want 1", raw["count"])
	}
	probes, _ := raw["probes"].([]any)
	if len(probes) != 1 {
		t.Fatalf("probes len = %d, want 1", len(probes))
	}
	first, _ := probes[0].(map[string]any)
	if first["url"] != "https://example.com" || first["web_server"] != "nginx" {
		t.Fatalf("probe fields not preserved: %v", first)
	}
}

func TestExecute_DefaultAndParamPorts(t *testing.T) {
	fake := &fakeProber{}
	s := newWithProber(fake, 0)
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if fake.gotPorts != "80,443" {
		t.Fatalf("default ports = %q, want 80,443", fake.gotPorts)
	}

	fake2 := &fakeProber{}
	s2 := newWithProber(fake2, 0)
	if _, err := s2.Execute(context.Background(), sdk.Target{Host: "  example.com  ", Params: map[string]string{"ports": "8080,8443"}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if fake2.gotHost != "example.com" {
		t.Fatalf("host not trimmed: %q", fake2.gotHost)
	}
	if fake2.gotPorts != "8080,8443" {
		t.Fatalf("ports param not passed: %q", fake2.gotPorts)
	}
}

func TestExecute_EmptyHost(t *testing.T) {
	fake := &fakeProber{}
	s := newWithProber(fake, 0)
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "   "}); err == nil {
		t.Fatal("expected error for empty host")
	}
	if fake.calls != 0 {
		t.Fatalf("prober called %d times; want 0", fake.calls)
	}
}

func TestExecute_ProberError(t *testing.T) {
	boom := errors.New("dial timeout")
	fake := &fakeProber{err: boom}
	s := newWithProber(fake, 0)
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestExecute_PerCallTimeout(t *testing.T) {
	fake := &fakeProber{block: true}
	s := newWithProber(fake, 20*time.Millisecond)
	start := time.Now()
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout not honoured; took %s", time.Since(start))
	}
}

func TestExecute_InitError(t *testing.T) {
	s := &scanner{initErr: errors.New("bad options")}
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); err == nil {
		t.Fatal("expected init error to surface from Execute")
	}
}

func TestCapabilityAndPrepare(t *testing.T) {
	s := &scanner{}
	if c, _ := s.Capability(context.Background()); c != "httpprobe" {
		t.Fatalf("capability = %q", c)
	}
	if err := s.Prepare(context.Background(), "tok"); err != nil {
		t.Fatalf("Prepare should be a no-op: %v", err)
	}
}
