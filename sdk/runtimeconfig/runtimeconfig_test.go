package runtimeconfig

import (
	"bytes"
	"testing"
)

func str(s string) *string { return &s }
func i64(n int64) *int64   { return &n }

func manifest() Manifest {
	return Manifest{ManifestVersion: Version, Capability: "httpprobe", Parameters: []Parameter{
		{Name: "threads", Kind: "integer", Scope: ScopePlugin, Default: str("25"), Minimum: i64(1), Maximum: i64(9007199254740993)},
		{Name: "mode", Kind: "enum", Scope: ScopeWorker, Default: str("fast"), Enum: []string{"fast", "full"}},
	}}
}

func TestCanonicalAndLargeInteger(t *testing.T) {
	d, err := Compile(manifest())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.CanonicalJSON()) == 0 || d.SHA256() == "" {
		t.Fatal("missing canonical identity")
	}
	raw := []byte(`{"manifest_version":1,"capability":"httpprobe","parameters":[{"name":"threads","kind":"integer","scope":"plugin","minimum":9007199254740993,"maximum":9007199254740993},{"name":"mode","kind":"enum","scope":"worker","enum":["fast"],"default":"fast"}]}`)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if *p.Manifest().Parameters[0].Minimum != 9007199254740993 {
		t.Fatalf("integer rounded: %d", *p.Manifest().Parameters[0].Minimum)
	}
}

func TestStrictValuesAndImmutability(t *testing.T) {
	m := manifest()
	d, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), d.CanonicalJSON()...)
	*m.Parameters[0].Minimum = 99
	*m.Parameters[0].Default = "99"
	m.Parameters[1].Enum[0] = "mutated"
	got := d.Manifest()
	got.Parameters[0].Default = str("mutated")
	got.Parameters[0].Minimum = i64(99)
	if !bytes.Equal(before, d.CanonicalJSON()) {
		t.Fatal("descriptor mutated")
	}
	p, w, err := d.ParseValues([]byte(`{"threads":"30"}`))
	if err != nil || p["threads"] != "30" || w["mode"] != "fast" {
		t.Fatalf("defaults/partition: %#v %#v %v", p, w, err)
	}
	for _, raw := range []string{`{"threads":"1","threads":"2"}`, `{"threads":"1"} {}`, `null`, `{"unknown":"x"}`, `{"threads":1}`} {
		if _, _, err := d.ParseValues([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, _, err := d.ParseValues([]byte(`{"threads":"0"}`)); err == nil {
		t.Fatal("accepted value below minimum")
	}
}

func TestRuntimeLimits(t *testing.T) {
	if _, err := Parse(bytes.Repeat([]byte(" "), maxJSONSize+1)); err == nil {
		t.Fatal("accepted oversized raw manifest")
	}
	m := manifest()
	m.Parameters = make([]Parameter, maxParameters+1)
	for n := range m.Parameters {
		m.Parameters[n] = Parameter{Name: "x", Kind: "string", Scope: ScopePlugin}
	}
	if _, err := Compile(m); err == nil {
		t.Fatal("accepted too many parameters")
	}
}

func TestStrictManifestParsingAndConstraints(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"manifest_version":1,"manifest_version":1,"capability":"httpprobe","parameters":[]}`),
		[]byte(`{"manifest_version":1,"capability":"httpprobe","parameters":[]} {}`),
		[]byte(`{"manifest_version":1,"capability":"httpprobe","parameters":[],"unknown":true}`),
		[]byte("\xff"),
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted invalid manifest %q", raw)
		}
	}
	bad := manifest()
	bad.Parameters[0].Scope = "host"
	if _, err := Compile(bad); err == nil {
		t.Fatal("accepted invalid scope")
	}
	bad = manifest()
	bad.Parameters[0].Kind = "duration"
	if _, err := Compile(bad); err == nil {
		t.Fatal("accepted invalid kind")
	}
	allowed := Manifest{ManifestVersion: Version, Capability: "httpprobe", Parameters: []Parameter{{Name: "methods", Kind: "string_list", Scope: ScopePlugin, ItemsEnum: []string{"GET", "POST"}}}}
	d, err := Compile(allowed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.ParseValues([]byte(`{"methods":"GET,DELETE"}`)); err == nil {
		t.Fatal("accepted item outside items_enum")
	}
}
