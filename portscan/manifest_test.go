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
	if err != nil || d.Manifest().ContractID != "vpt/portscan/v1" || d.Digest() != "sha256:d66d188d487aa75d7c7cd8243124f8646f417169a6d3f02a7eddfc586610ef3c" || d.ManifestDigest() != "sha256:055e08e21ea85b528d00cb588ab889c0eba239862ca9bb6898006cf3d2ece8a8" {
		t.Fatalf("manifest: %v", err)
	}
	var out bytes.Buffer
	handled, err := sdk.PrintManifestIfRequested(m, []string{"--print-manifest"}, &out)
	if err != nil || !handled || !bytes.Equal(out.Bytes(), d.CanonicalJSON()) {
		t.Fatalf("printed manifest mismatch: %v", err)
	}
}

func TestPortscanManifestParameters(t *testing.T) {
	m := manifest()
	if *m.Parameters[0].Default != "100" {
		t.Fatal("wrong default")
	}
	for _, value := range []string{"1-10", "80,443"} {
		if _, err := contract.NormalizeParameters(&m, map[string]string{"ports": value}); err != nil {
			t.Errorf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"wat", "10-1", "0"} {
		if _, err := contract.NormalizeParameters(&m, map[string]string{"ports": value}); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}
