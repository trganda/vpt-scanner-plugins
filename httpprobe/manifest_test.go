package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
	"github.com/trganda/vpt-scanner-plugins/sdk/runtimeconfig"
)

func TestManifest(t *testing.T) {
	m := manifest()
	d, err := contract.Compile(m)
	if err != nil || d.Manifest().ContractID != "vpt/httpprobe/v1" || d.Digest() != "sha256:10f48d7701024fba0d350af30cf956ba6b796638580b3700c0bc02c2a3a87e92" || d.ManifestDigest() != "sha256:bbb5c1c462c61902519efcce8eb9d81e3473aba5337754bf6fb3e25d376e8065" {
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
	normalized, err := contract.NormalizeParameters(&m, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if normalized["request_timeout_seconds"] != "10" || normalized["follow_redirects"] != "true" || normalized["tech_detect"] != "true" || normalized["asn"] != "false" {
		t.Fatalf("primary defaults: %#v", normalized)
	}
	if _, ok := normalized["methods"]; ok {
		t.Fatal("optional methods inherited a value")
	}
	if _, err := contract.NormalizeParameters(&m, map[string]string{"methods": "GET,INVALID"}); err == nil {
		t.Fatal("invalid method accepted")
	}
}

func TestLegacyManifestIdentityIsStable(t *testing.T) {
	d, err := contract.Compile(legacyManifest())
	if err != nil {
		t.Fatal(err)
	}
	if d.Digest() != "sha256:1af8072bfd6fbd94bbee1bffcf46d2697b4e9fa646d2a9c916d7545ec1c80575" || d.ManifestDigest() != "sha256:dcf278c8d55dfcee80d796e63ea01f7da23550242cf020761975d29982bc5b80" {
		t.Fatalf("legacy identity changed: %s %s", d.Digest(), d.ManifestDigest())
	}
}

func TestPrintsCompatibleAndRuntimeManifestsCanonically(t *testing.T) {
	primary := manifest()
	legacy := legacyManifest()
	runtime := runtimeManifest()
	legacyDescriptor, err := contract.Compile(legacy)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDescriptor, err := runtimeconfig.Compile(runtime)
	if err != nil {
		t.Fatal(err)
	}
	var compatible bytes.Buffer
	handled, err := sdk.PrintManifestsIfRequested(primary, []contract.Manifest{legacy}, &runtime, []string{"--print-compatible-contracts"}, &compatible)
	if err != nil || !handled {
		t.Fatalf("print compatible: %v", err)
	}
	wantCompatible, _ := json.Marshal([]json.RawMessage{legacyDescriptor.CanonicalJSON()})
	if !bytes.Equal(compatible.Bytes(), wantCompatible) {
		t.Fatalf("compatible bytes differ: %s", compatible.Bytes())
	}
	var runtimeOut bytes.Buffer
	handled, err = sdk.PrintManifestsIfRequested(primary, nil, &runtime, []string{"--print-runtime"}, &runtimeOut)
	if err != nil || !handled || !bytes.Equal(runtimeOut.Bytes(), runtimeDescriptor.CanonicalJSON()) {
		t.Fatalf("print runtime: %v %s", err, runtimeOut.Bytes())
	}
}
