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
	if err != nil || d.Manifest().ContractID != "vpt/portscan/v1" || d.Digest() != "sha256:f97be3931229c807a0904eafb3f56b3974f7a771e676bb012422f25c129d6540" || d.ManifestDigest() != "sha256:6c810d11b14520ca2d2d9df56099959cc5647862740d872766aeb20a01c22172" {
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
