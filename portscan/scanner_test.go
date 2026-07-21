package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// fakeScanner is a double for the package-private portScanner port so these
// tests don't pull naabu or live network in. Plain stdlib testing keeps the
// plugin module free of ginkgo.
type fakeScanner struct {
	ports    []PortResult
	err      error
	calls    int
	gotHost  string
	gotPorts string
	block    bool
}

func (f *fakeScanner) Scan(ctx context.Context, host, ports string) ([]PortResult, error) {
	f.calls++
	f.gotHost = host
	f.gotPorts = ports
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.ports, f.err
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
	fake := &fakeScanner{ports: []PortResult{{Port: 80, Protocol: "tcp"}, {Port: 443, Protocol: "tcp"}}}
	s := newWithScanner(fake, 0)

	var events []sdk.Event
	res, err := s.ExecuteStream(context.Background(), sdk.Target{Host: "example.com"}, func(e sdk.Event) error { events = append(events, e); return nil })
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Capability != capability {
		t.Fatalf("capability = %q, want %q", res.Capability, capability)
	}
	if len(events) != 2 || events[0].Type != "scan_started" || events[1].Type != "scan_completed" {
		t.Fatalf("events = %+v", events)
	}
	raw := decodeRaw(t, res)
	if raw["host"] != "example.com" {
		t.Fatalf("raw host = %v", raw["host"])
	}
	if raw["count"] != float64(2) {
		t.Fatalf("raw count = %v, want 2", raw["count"])
	}
	if fake.gotHost != "example.com" || fake.gotPorts != "100" {
		t.Fatalf("scanner saw host=%q ports=%q; want example.com / 100 (default)", fake.gotHost, fake.gotPorts)
	}
}

func TestExecute_PortsParamAndTrim(t *testing.T) {
	fake := &fakeScanner{}
	s := newWithScanner(fake, 0)

	_, err := s.Execute(context.Background(), sdk.Target{
		Host:   "  example.com  ",
		Params: map[string]string{"ports": "22,80,443"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if fake.gotHost != "example.com" {
		t.Fatalf("host not trimmed: %q", fake.gotHost)
	}
	if fake.gotPorts != "22,80,443" {
		t.Fatalf("ports param not passed: %q", fake.gotPorts)
	}
}

func TestExecute_EmptyHost(t *testing.T) {
	fake := &fakeScanner{}
	s := newWithScanner(fake, 0)

	_, err := s.Execute(context.Background(), sdk.Target{Host: "   "})
	if err == nil {
		t.Fatal("expected error for empty host")
	}
	if fake.calls != 0 {
		t.Fatalf("scanner called %d times; want 0", fake.calls)
	}
}

func TestExecute_ScannerError(t *testing.T) {
	boom := errors.New("connection refused")
	fake := &fakeScanner{err: boom}
	s := newWithScanner(fake, 0)

	_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestExecute_PerCallTimeout(t *testing.T) {
	fake := &fakeScanner{block: true}
	s := newWithScanner(fake, 20*time.Millisecond)

	start := time.Now()
	_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout not honoured; took %s", time.Since(start))
	}
}

func TestCapabilityAndPrepare(t *testing.T) {
	s := newScanner()
	if c, _ := s.Capability(context.Background()); c != "portscan" {
		t.Fatalf("capability = %q", c)
	}
	if err := s.Prepare(context.Background(), "tok"); err != nil {
		t.Fatalf("Prepare should be a no-op: %v", err)
	}
}
