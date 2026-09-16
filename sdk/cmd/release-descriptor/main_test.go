package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk/release"
)

func TestRunScopedRelease(t *testing.T) {
	dist := t.TempDir()
	for _, architecture := range []string{"amd64", "arm64"} {
		if err := os.WriteFile(filepath.Join(dist, "portscan_linux_"+architecture), []byte(architecture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	err := run([]string{"-dist", dist, "-repository", "trganda/vpt-scanner-plugins", "-tag", "plugin-portscan-v1.2.3", "-commit", strings.Repeat("a", 40)}, &output)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := release.Parse(output.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptor.Plugins) != 1 || descriptor.Plugins[0].Capability != "portscan" || descriptor.Plugins[0].PluginVersion != "v1.2.3" {
		t.Fatalf("unexpected descriptor: %+v", descriptor)
	}
}
