package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

type fakeEnumerator struct {
	domain string
	opts   cloudOptions
	assets []Asset
	failed int
	err    error
}

func (f *fakeEnumerator) Enumerate(_ context.Context, domain string, opts cloudOptions) ([]Asset, int, error) {
	f.domain, f.opts = domain, opts
	return f.assets, f.failed, f.err
}

func TestScannerReturnsScopedAssets(t *testing.T) {
	fake := &fakeEnumerator{assets: []Asset{{Host: "api.example.test", Provider: "cloudflare", Service: "dns"}}, failed: 1}
	s := newWithEnumerator(fake, config{ProviderConfig: "/run/secrets/cloudlist.yaml"})
	result, err := s.Execute(context.Background(), sdk.Target{Host: "example.test", Params: map[string]string{"providers": "cloudflare,aws", "services": "dns"}})
	if err != nil {
		t.Fatal(err)
	}
	if fake.domain != "example.test" || fake.opts.ProviderConfig != "/run/secrets/cloudlist.yaml" || len(fake.opts.Providers) != 2 || len(fake.opts.Services) != 1 {
		t.Fatalf("unexpected enumerate invocation: %#v", fake)
	}
	var raw struct {
		Assets          []Asset `json:"assets"`
		FailedProviders int     `json:"failed_providers"`
	}
	if err := json.Unmarshal(result.RawJSON, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Assets) != 1 || raw.FailedProviders != 1 {
		t.Fatalf("unexpected raw result: %#v", raw)
	}
}

func TestCloudlistOutputMapperSkipsInvalidHosts(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"assets": []Asset{{Host: "api.example.test"}, {Host: "invalid host"}}})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := cloudlistOutputMapper(sdk.Target{}, sdk.Result{RawJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 1 || len(outputs[0].Values) != 1 || outputs[0].Values[0].String() != "api.example.test" {
		t.Fatalf("unexpected outputs: %#v", outputs)
	}
}

func TestWithinDomain(t *testing.T) {
	for _, tc := range []struct {
		host, domain string
		want         bool
	}{{"api.example.test", "example.test", true}, {"example.test", "example.test", true}, {"notexample.test", "example.test", false}, {"api.other.test", "example.test", false}} {
		if got := withinDomain(tc.host, tc.domain); got != tc.want {
			t.Errorf("withinDomain(%q, %q) = %v, want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}
