package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func TestManifest(t *testing.T) {
	m := manifest()
	d, err := contract.Compile(m)
	if err != nil || d.Manifest().ContractID != "vpt/subdomain/v1" || d.Digest() != "sha256:7f7aed6a5920deffb4051a6c4293b32f099be568f2945be32f5cc33c0c669b7e" || d.ManifestDigest() != "sha256:7e630a31d89af0f52c39645070775ceedb0567c72441bfef09db74a32b05181f" {
		t.Fatalf("manifest: %v", err)
	}
	var out bytes.Buffer
	handled, err := sdk.PrintManifestIfRequested(m, []string{"--print-manifest"}, &out)
	if err != nil || !handled || !bytes.Equal(out.Bytes(), d.CanonicalJSON()) {
		t.Fatalf("printed manifest mismatch: %v", err)
	}
}

func TestSubdomainOutputMapper(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want []string
		fail bool
	}{
		{"ordered", `{"subdomains":["B.Example.COM","a.example.com"]}`, []string{"b.example.com", "a.example.com"}, false},
		{"empty", `{"subdomains":[]}`, []string{}, false},
		{"bad host", `{"subdomains":["bad host"]}`, nil, true},
		{"bad raw", `{`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outs, err := subdomainOutputMapper(sdk.Target{}, sdk.Result{RawJSON: []byte(tc.raw)})
			if (err != nil) != tc.fail {
				t.Fatalf("error = %v", err)
			}
			if tc.fail {
				return
			}
			if len(outs) != 1 || len(outs[0].Values) != len(tc.want) {
				t.Fatalf("outputs = %#v", outs)
			}
			for i, want := range tc.want {
				if got := outs[0].Values[i].String(); got != want {
					t.Errorf("value[%d] = %q", i, got)
				}
			}
		})
	}
	outs, _ := subdomainOutputMapper(sdk.Target{}, sdk.Result{RawJSON: mustJSON(map[string]any{"subdomains": []string{"a.example.com", "a.example.com"}})})
	validated, err := contract.ValidateOutputs(manifest(), outs)
	if err != nil || len(validated[0].Values) != 1 {
		t.Fatalf("dedupe: %v %#v", err, validated)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
