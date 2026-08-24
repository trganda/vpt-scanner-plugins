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
	if err != nil || d.Manifest().ContractID != "vpt/vuln/v1" || d.Digest() != "sha256:5668a409a8c1b7500b209b524290ac404f51ace3a04a60def1045a5f1bea104f" || d.ManifestDigest() != "sha256:558ab3541cb57697eed5b150e6da0f9dc1d1ebd68b4f145e472ef36176a1abe6" {
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
