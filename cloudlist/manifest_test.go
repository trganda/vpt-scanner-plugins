package main

import (
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func TestManifestCompiles(t *testing.T) {
	if _, err := contract.Compile(manifest()); err != nil {
		t.Fatal(err)
	}
}
