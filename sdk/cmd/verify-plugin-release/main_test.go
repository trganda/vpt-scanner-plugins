package main

import (
	"strings"
	"testing"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/release"
)

func TestVerify(t *testing.T) {
	descriptor := release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		Source:        release.Source{Repository: "trganda/vpt-scanner-plugins", Tag: "plugin-portscan-v1.2.3", Commit: strings.Repeat("a", 40)},
		SDKVersion:    sdk.Version, ProtocolVersion: sdk.ContractProtocolVersion,
		Plugins: []release.Plugin{{Capability: "portscan", PluginVersion: "v1.2.3", Artifacts: []release.Artifact{
			{Name: "portscan_linux_amd64", OS: "linux", Architecture: "amd64", SHA256: "sha256:" + strings.Repeat("1", 64)},
			{Name: "portscan_linux_arm64", OS: "linux", Architecture: "arm64", SHA256: "sha256:" + strings.Repeat("2", 64)},
		}, Features: []string{"execute_stream", "typed_contracts"}, RuntimeRequirements: map[string]string{"libc": "glibc", "os": "linux"}}},
	}
	description := sdk.Description{Capability: "portscan", PluginVersion: "v1.2.3", SDKVersion: sdk.Version, SourceCommit: descriptor.Source.Commit, ProtocolVersion: sdk.ContractProtocolVersion, Features: []string{"execute_stream", "typed_contracts"}, RuntimeRequirements: map[string]string{"libc": "glibc", "os": "linux"}}
	if err := verify(description, descriptor, "portscan"); err != nil {
		t.Fatal(err)
	}
	description.SourceCommit = strings.Repeat("b", 40)
	if err := verify(description, descriptor, "portscan"); err == nil {
		t.Fatal("mismatched description accepted")
	}
}
