package main

import (
	"bytes"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func TestManifest(t *testing.T) {
	m := manifest()
	d, err := contract.Compile(m)
	if err != nil || d.Manifest().ContractID != "vpt/vuln/v1" || d.Digest() != "sha256:dff360d70a179e58e7f18c90d367c3b102f42509f2b6ae3b933384099318f0a5" || d.ManifestDigest() != "sha256:f96ce9fb1753f9d8e60926a7a19aa8fe2bad34cc4a784e9e1cfc28248c898458" {
		t.Fatalf("manifest: %v", err)
	}
	var out bytes.Buffer
	handled, err := sdk.PrintManifestIfRequested(m, []string{"--print-manifest"}, &out)
	if err != nil || !handled || !bytes.Equal(out.Bytes(), d.CanonicalJSON()) {
		t.Fatalf("printed manifest mismatch: %v", err)
	}
}

func TestNucleiTargetMapper(t *testing.T) {
	for _, tc := range []struct {
		name, severity string
		want           bool
	}{
		{"default all", "all", false}, {"concrete", "high", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nucleiTargetMapper(sdk.Target{Params: map[string]string{"severity": tc.severity, "tags": "cve", "ids": "CVE-1"}})
			if err != nil {
				t.Fatal(err)
			}
			_, ok := got.Params["severity"]
			if ok != tc.want || got.Params["tags"] != "cve" || got.Params["ids"] != "CVE-1" {
				t.Fatalf("mapped = %#v", got.Params)
			}
		})
	}
}

func TestNucleiManifestContract(t *testing.T) {
	m := manifest()
	d, err := contract.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Manifest().Inputs[0].AcceptedTypes) != 2 {
		t.Fatal("expected host and URL inputs")
	}
	if _, err := contract.NormalizeParameters(&m, map[string]string{"severity": "invalid"}); err == nil {
		t.Fatal("invalid severity accepted")
	}
}
