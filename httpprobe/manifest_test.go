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
	if err != nil || d.Manifest().ContractID != "vpt/httpprobe/v1" || d.Digest() != "sha256:1af8072bfd6fbd94bbee1bffcf46d2697b4e9fa646d2a9c916d7545ec1c80575" || d.ManifestDigest() != "sha256:dcf278c8d55dfcee80d796e63ea01f7da23550242cf020761975d29982bc5b80" {
		t.Fatalf("manifest: %v", err)
	}
	var out bytes.Buffer
	handled, err := sdk.PrintManifestIfRequested(m, []string{"--print-manifest"}, &out)
	if err != nil || !handled || !bytes.Equal(out.Bytes(), d.CanonicalJSON()) {
		t.Fatalf("printed manifest mismatch: %v", err)
	}
}

func TestHTTPProbeManifestParameters(t *testing.T) {
	m := manifest()
	if *m.Parameters[0].Default != "80,443" {
		t.Fatal("wrong default")
	}
	if _, err := contract.NormalizeParameters(&m, map[string]string{"ports": " 80, 443 "}); err != nil {
		t.Fatal(err)
	}
	if _, err := contract.NormalizeParameters(&m, map[string]string{"unknown": "1"}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
}
