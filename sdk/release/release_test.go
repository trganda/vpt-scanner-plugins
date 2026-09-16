package release

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func testDescriptor() Descriptor {
	return Descriptor{
		SchemaVersion:   SchemaVersion,
		Source:          Source{Repository: "trganda/vpt-scanner-plugins", Tag: "plugin-subdomain-v1.2.3", Commit: strings.Repeat("a", 40)},
		SDKVersion:      "v0.3.0",
		ProtocolVersion: 1,
		Plugins: []Plugin{{
			Capability:    "subdomain",
			PluginVersion: "v1.2.3",
			Artifacts: []Artifact{
				{Name: "subdomain_linux_amd64", OS: "linux", Architecture: "amd64", SHA256: "sha256:" + strings.Repeat("1", 64)},
				{Name: "subdomain_linux_arm64", OS: "linux", Architecture: "arm64", SHA256: "sha256:" + strings.Repeat("2", 64)},
			},
			Features:            []string{"check", "execute_stream"},
			RuntimeRequirements: map[string]string{"libc": "glibc", "os": "linux"},
		}},
	}
}

func aggregateDescriptor() Descriptor {
	descriptor := testDescriptor()
	descriptor.Source.Tag = "v1.2.3"
	descriptor.Plugins = nil
	for i, capability := range []string{"subdomain", "portscan", "httpprobe", "vuln", "katana", "cloudlist"} {
		digest := string(rune('1' + i))
		descriptor.Plugins = append(descriptor.Plugins, Plugin{
			Capability:    capability,
			PluginVersion: "v1.2.3",
			Artifacts: []Artifact{
				{Name: capability + "_linux_amd64", OS: "linux", Architecture: "amd64", SHA256: "sha256:" + strings.Repeat(digest, 64)},
				{Name: capability + "_linux_arm64", OS: "linux", Architecture: "arm64", SHA256: "sha256:" + strings.Repeat(digest, 64)},
			},
			Features:            []string{},
			RuntimeRequirements: map[string]string{},
		})
	}
	return descriptor
}

func TestCanonicalRoundTrip(t *testing.T) {
	descriptor := testDescriptor()
	canonical, err := Canonical(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("\n")) {
		t.Fatal("canonical descriptor contains a newline")
	}
	parsed, err := Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Canonical(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, roundTrip) {
		t.Fatalf("canonical round trip changed bytes\nfirst: %s\nsecond: %s", canonical, roundTrip)
	}
	wantPrefix := `{"plugins":[{"artifacts":[{"architecture":"amd64"`
	if !strings.HasPrefix(string(canonical), wantPrefix) {
		t.Fatalf("object keys are not canonical: %s", canonical)
	}
}

func TestParseStrictness(t *testing.T) {
	canonical, err := Canonical(testDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		append(append([]byte(nil), canonical...), []byte(` {}`)...),
		bytes.Replace(canonical, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		bytes.Replace(canonical, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
		bytes.Replace(canonical, []byte(`"features":["check","execute_stream"]`), []byte(`"features":null`), 1),
		bytes.Replace(canonical, []byte(`"repository":"trganda/vpt-scanner-plugins"`), []byte(`"repository":"\ud800"`), 1),
		[]byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)),
	}
	for _, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("accepted invalid descriptor: %s", raw)
		}
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]func(*Descriptor){
		"schema":            func(d *Descriptor) { d.SchemaVersion = 2 },
		"repository":        func(d *Descriptor) { d.Source.Repository = "https://github.com/trganda/vpt-scanner-plugins" },
		"repository dot":    func(d *Descriptor) { d.Source.Repository = "../vpt-scanner-plugins" },
		"tag":               func(d *Descriptor) { d.Source.Tag = "latest" },
		"leading-zero tag":  func(d *Descriptor) { d.Source.Tag = "plugin-subdomain-v01.2.3" },
		"commit":            func(d *Descriptor) { d.Source.Commit = strings.Repeat("A", 40) },
		"SDK version":       func(d *Descriptor) { d.SDKVersion = "0.3" },
		"protocol":          func(d *Descriptor) { d.ProtocolVersion = 2 },
		"capability":        func(d *Descriptor) { d.Plugins[0].Capability = "unknown" },
		"plugin version":    func(d *Descriptor) { d.Plugins[0].PluginVersion = "v1.2.4" },
		"artifact name":     func(d *Descriptor) { d.Plugins[0].Artifacts[0].Name = "other_linux_amd64" },
		"artifact platform": func(d *Descriptor) { d.Plugins[0].Artifacts[0].Architecture = "arm64" },
		"artifact digest":   func(d *Descriptor) { d.Plugins[0].Artifacts[0].SHA256 = strings.Repeat("1", 64) },
		"duplicate feature": func(d *Descriptor) { d.Plugins[0].Features = []string{"check", "check"} },
		"feature order":     func(d *Descriptor) { d.Plugins[0].Features = []string{"execute_stream", "check"} },
		"nil requirements":  func(d *Descriptor) { d.Plugins[0].RuntimeRequirements = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			descriptor := testDescriptor()
			mutate(&descriptor)
			if err := Validate(descriptor); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
		})
	}

	descriptor := aggregateDescriptor()
	if err := Validate(descriptor); err != nil {
		t.Fatalf("aggregate descriptor rejected: %v", err)
	}
	descriptor.Plugins[0], descriptor.Plugins[1] = descriptor.Plugins[1], descriptor.Plugins[0]
	if err := Validate(descriptor); err == nil {
		t.Fatal("non-canonical capability order accepted")
	}

	descriptor = testDescriptor()
	descriptor.Plugins = append(descriptor.Plugins, descriptor.Plugins[0])
	if err := Validate(descriptor); err == nil {
		t.Fatal("multi-plugin scoped release accepted")
	}

	descriptor = testDescriptor()
	descriptor.Source.Tag = "v1.2.3"
	if err := Validate(descriptor); err == nil {
		t.Fatal("partial aggregate release accepted")
	}

	descriptor = testDescriptor()
	descriptor.Plugins[0].Features = make([]string, 40000)
	for i := range descriptor.Plugins[0].Features {
		descriptor.Plugins[0].Features[i] = fmt.Sprintf("feature_%05d", i)
	}
	if err := Validate(descriptor); err == nil {
		t.Fatal("oversized programmatic descriptor accepted")
	}
}
