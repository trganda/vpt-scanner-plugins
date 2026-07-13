package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// fakeEngine is a double for the engine port so Execute tests don't drag the
// nuclei SDK in.
type fakeEngine struct {
	findings []Finding
	err      error
	gotHost  string
}

func (f *fakeEngine) Scan(_ context.Context, target string, _ map[string]string) ([]Finding, error) {
	f.gotHost = target
	return f.findings, f.err
}

func TestExecute_RawShape(t *testing.T) {
	fake := &fakeEngine{findings: []Finding{
		{TemplateID: "cve-2021-1234", Severity: "high", Host: "https://t", CVEIDs: []string{"CVE-2021-1234"}},
	}}
	s := newWithEngine(fake)

	res, err := s.Execute(context.Background(), sdk.Target{Host: "https://t"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Capability != capability {
		t.Fatalf("capability = %q", res.Capability)
	}
	var raw map[string]any
	if err := json.Unmarshal(res.RawJSON, &raw); err != nil {
		t.Fatalf("raw_json invalid: %v", err)
	}
	if raw["host"] != "https://t" {
		t.Fatalf("host = %v", raw["host"])
	}
	if raw["count"] != float64(1) {
		t.Fatalf("count = %v, want 1", raw["count"])
	}
	if fake.gotHost != "https://t" {
		t.Fatalf("engine saw host %q", fake.gotHost)
	}
}

func TestExecute_EngineError(t *testing.T) {
	boom := errors.New("nuclei exploded")
	s := newWithEngine(&fakeEngine{err: boom})
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "https://t"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestExecute_InitError(t *testing.T) {
	s := &scanner{initErr: errors.New("template dir required")}
	if _, err := s.Execute(context.Background(), sdk.Target{Host: "https://t"}); err == nil {
		t.Fatal("expected init error to surface from Execute")
	}
	if err := s.Prepare(context.Background(), "tok"); err == nil {
		t.Fatal("expected init error to surface from Prepare")
	}
}

func TestCapability(t *testing.T) {
	s := &scanner{}
	if c, _ := s.Capability(context.Background()); c != "vuln" {
		t.Fatalf("capability = %q", c)
	}
}

// Prepare's template-sync path: assert the bundle fetch carries the node JWT
// and that an empty token omits the header. Exercises the syncer/fetchBundle
// directly (the on-disk Sync is covered by the cache write path).
func TestFetchBundle_SetsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(bundleResponse{Success: true, Data: []bundleEntry{}})
	}))
	defer srv.Close()

	s := &syncer{bundleURL: srv.URL, httpClient: srv.Client()}
	if _, err := s.fetchBundle(context.Background(), "template", "node-jwt"); err != nil {
		t.Fatalf("fetchBundle: %v", err)
	}
	if gotAuth != "Bearer node-jwt" {
		t.Fatalf("Authorization = %q, want Bearer node-jwt", gotAuth)
	}
}

func TestFetchBundle_NoTokenOmitsHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(bundleResponse{Success: true, Data: []bundleEntry{}})
	}))
	defer srv.Close()

	s := &syncer{bundleURL: srv.URL, httpClient: srv.Client()}
	if _, err := s.fetchBundle(context.Background(), "template", ""); err != nil {
		t.Fatalf("fetchBundle: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty", gotAuth)
	}
}

func TestFetchBundle_401Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := &syncer{bundleURL: srv.URL, httpClient: srv.Client()}
	if _, err := s.fetchBundle(context.Background(), "template", "x"); err == nil {
		t.Fatal("expected error on 401")
	}
}

// Unwraps the response envelope's data array on success.
func TestFetchBundle_ReturnsEnvelopeData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(bundleResponse{
			Success: true,
			Data:    []bundleEntry{{ID: "tmpl-1", PresignedURL: "https://s3/tmpl-1"}},
		})
	}))
	defer srv.Close()

	s := &syncer{bundleURL: srv.URL, httpClient: srv.Client()}
	entries, err := s.fetchBundle(context.Background(), "template", "x")
	if err != nil {
		t.Fatalf("fetchBundle: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "tmpl-1" {
		t.Fatalf("entries = %+v, want one entry tmpl-1", entries)
	}
}

// A 200 envelope with success=false surfaces the error message.
func TestFetchBundle_UnsuccessfulEnvelopeErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(bundleResponse{
			Success: false,
			Error:   &bundleError{Code: "internal", Message: "boom"},
		})
	}))
	defer srv.Close()

	s := &syncer{bundleURL: srv.URL, httpClient: srv.Client()}
	if _, err := s.fetchBundle(context.Background(), "template", "x"); err == nil {
		t.Fatal("expected error on success=false envelope")
	}
}
