package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// fakeEnum is a double for the enumerator port so these tests don't drag the
// subfinder SDK or live network into the unit suite.
type fakeEnum struct {
	findings []Finding
	err      error
	calls    int
	gotHost  string
	block    bool
}

func (f *fakeEnum) Enumerate(ctx context.Context, domain string) ([]Finding, error) {
	f.calls++
	f.gotHost = domain
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.findings, f.err
}

func decodeRaw(t *testing.T, r sdk.Result) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.RawJSON, &m); err != nil {
		t.Fatalf("raw_json invalid: %v", err)
	}
	return m
}

func TestExecute_Aggregates(t *testing.T) {
	fake := &fakeEnum{findings: []Finding{
		{Host: "api.example.com", Source: "crtsh"},
		{Host: "www.example.com", Source: "crtsh"},
		{Host: "mail.example.com", Source: "hackertarget"},
	}}
	s := newWithEnumerator(fake, 0)

	var events []sdk.Event
	res, err := s.ExecuteStream(context.Background(), sdk.Target{Host: "example.com"}, func(e sdk.Event) error { events = append(events, e); return nil })
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Capability != capability {
		t.Fatalf("capability = %q", res.Capability)
	}
	if len(events) != 2 || events[0].Type != "scan_started" || events[1].Type != "scan_completed" {
		t.Fatalf("events = %+v", events)
	}
	raw := decodeRaw(t, res)
	if raw["domain"] != "example.com" {
		t.Fatalf("domain = %v", raw["domain"])
	}
	if raw["count"] != float64(3) {
		t.Fatalf("count = %v, want 3", raw["count"])
	}
	subs, _ := raw["subdomains"].([]any)
	if len(subs) != 3 {
		t.Fatalf("subdomains len = %d, want 3", len(subs))
	}
	bySrc, _ := raw["by_source"].(map[string]any)
	crtsh, _ := bySrc["crtsh"].([]any)
	if len(crtsh) != 2 {
		t.Fatalf("by_source[crtsh] len = %d, want 2", len(crtsh))
	}
	if fake.gotHost != "example.com" {
		t.Fatalf("enumerator saw host %q", fake.gotHost)
	}
}

func TestExecute_TrimsHost(t *testing.T) {
	fake := &fakeEnum{findings: []Finding{{Host: "a.example.com", Source: "crtsh"}}}
	s := newWithEnumerator(fake, 0)
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "  example.com  "}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if fake.gotHost != "example.com" {
		t.Fatalf("host not trimmed: %q", fake.gotHost)
	}
}

func TestExecute_EmptyHost(t *testing.T) {
	fake := &fakeEnum{}
	s := newWithEnumerator(fake, 0)
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "   "}); err == nil {
		t.Fatal("expected error for empty host")
	}
	if fake.calls != 0 {
		t.Fatalf("enumerator called %d times; want 0", fake.calls)
	}
}

func TestExecute_EnumeratorError(t *testing.T) {
	boom := errors.New("source rate-limited")
	fake := &fakeEnum{err: boom}
	s := newWithEnumerator(fake, 0)
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestExecute_PerCallTimeout(t *testing.T) {
	fake := &fakeEnum{block: true}
	s := newWithEnumerator(fake, 20*time.Millisecond)
	start := time.Now()
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout not honoured; took %s", time.Since(start))
	}
}

func TestExecute_InitError(t *testing.T) {
	s := &scanner{initErr: errors.New("bad provider config")}
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"}); err == nil {
		t.Fatal("expected init error to surface from Execute")
	}
}

func TestCapabilityAndPrepare(t *testing.T) {
	s := &scanner{}
	if c, _ := s.Capability(context.Background()); c != "subdomain" {
		t.Fatalf("capability = %q", c)
	}
	if err := s.Prepare(context.Background(), "tok"); err != nil {
		t.Fatalf("Prepare should be a no-op: %v", err)
	}
}
