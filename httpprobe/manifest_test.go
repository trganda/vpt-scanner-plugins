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
	if err != nil || d.Manifest().ContractID != "vpt/httpprobe/v1" || d.Digest() != "sha256:1cad3074d8379a5c25f04aee8b1cb2761d2aba163dacaea796e1981ce8ae5699" || d.ManifestDigest() != "sha256:e9f4f3bc4e946d651abf9191e19e513b485d81da70970690fc5fa1707ed81b3f" {
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
