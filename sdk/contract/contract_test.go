package contract

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func testManifest() Manifest {
	return Manifest{ManifestVersion: 1, Capability: "portscan", ContractID: "vpt/portscan/v1",
		Inputs:     []Input{{Name: "target", AcceptedTypes: []string{"domain/v1", "host/v1", "url/v1"}, Cardinality: "one"}},
		Outputs:    []Output{{Name: "host", Type: "host/v1", Cardinality: "one"}},
		Parameters: []Parameter{{Name: "mode", Kind: "enum", Enum: []string{"fast", "full"}, Default: strptr("fast")}}}
}
func strptr(s string) *string { return &s }
func intptr(n int) *int       { return &n }
func int64ptr(n int64) *int64 { return &n }

func TestCanonicalAndDigests(t *testing.T) {
	a := []byte(`{"contract_id":"vpt/portscan/v1","capability":"portscan","manifest_version":1,"outputs":[{"cardinality":"one","name":"host","type":"host/v1"}],"inputs":[{"cardinality":"one","accepted_types":["domain/v1","host/v1","url/v1"],"name":"target"}],"parameters":[{"default":"fast","enum":["fast","full"],"kind":"enum","name":"mode"}]}`)
	b := []byte(`{"parameters":[{"name":"mode","kind":"enum","enum":["fast","full"],"default":"fast"}],"inputs":[{"name":"target","accepted_types":["domain/v1","host/v1","url/v1"],"cardinality":"one"}],"manifest_version":1,"capability":"portscan","contract_id":"vpt/portscan/v1","outputs":[{"name":"host","type":"host/v1","cardinality":"one"}]}`)
	da, err := Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"capability":"portscan","contract_id":"vpt/portscan/v1","inputs":[{"accepted_types":["domain/v1","host/v1","url/v1"],"cardinality":"one","name":"target"}],"manifest_version":1,"outputs":[{"cardinality":"one","name":"host","type":"host/v1"}],"parameters":[{"default":"fast","enum":["fast","full"],"kind":"enum","name":"mode","required":false}]}`
	wantSemantic := wantCanonical
	wantContractDigest := "sha256:f88392b698b0dd2c7fa29b43f30871ec57d04d196ee4b02d27daac27651d86fa"
	wantManifestDigest := wantContractDigest
	if string(da.CanonicalJSON()) != wantCanonical || string(da.SemanticJSON()) != wantSemantic || da.Digest() != wantContractDigest || da.ManifestDigest() != wantManifestDigest {
		t.Fatalf("golden mismatch\ncanonical: %q\nsemantic: %q\ncontract: %q\nmanifest: %q", da.CanonicalJSON(), da.SemanticJSON(), da.Digest(), da.ManifestDigest())
	}
	if !bytes.Equal(da.CanonicalJSON(), db.CanonicalJSON()) || da.Digest() != db.Digest() {
		t.Fatal("reordered manifest changed canonical result")
	}
	if bytes.Contains(da.CanonicalJSON(), []byte("\n")) || bytes.Contains(da.CanonicalJSON(), []byte("\\u003c")) {
		t.Fatal("canonical JSON is not compact/unescaped")
	}
	m := da.Manifest()
	m.Display = &Display{Name: "shown"}
	dc, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	if dc.Digest() != da.Digest() || dc.ManifestDigest() == da.ManifestDigest() {
		t.Fatal("display hashing is wrong")
	}
	wantDisplayManifestDigest := "sha256:03d8607f1546434469a1b38f062e309d94f371ce74d7d55b788549888486c759"
	if dc.ManifestDigest() != wantDisplayManifestDigest {
		t.Fatalf("display manifest digest = %q; canonical = %q", dc.ManifestDigest(), dc.CanonicalJSON())
	}
	m.Display.Name = "shown <&>"
	escaped, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(escaped.CanonicalJSON(), []byte(`shown <&>`)) {
		t.Fatalf("presentation text was unnecessarily escaped: %s", escaped.CanonicalJSON())
	}
	reordered := da.Manifest()
	reordered.Inputs[0].AcceptedTypes[0], reordered.Inputs[0].AcceptedTypes[1] = reordered.Inputs[0].AcceptedTypes[1], reordered.Inputs[0].AcceptedTypes[0]
	dr, err := Compile(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if dr.Digest() == da.Digest() {
		t.Fatal("accepted type order did not affect semantic digest")
	}
	ordered, err := canonical(map[string]any{"é": "second", "z": "first"})
	if err != nil || string(ordered) != `{"z":"first","é":"second"}` {
		t.Fatalf("UTF-8 key order: %s %v", ordered, err)
	}
}

func TestParseStrictness(t *testing.T) {
	for _, raw := range []string{`{"a":1}{"b":2}`, `{"a":1,"a":2}`, `{"a":null}`, `{"a":"\ud800"}`, `{"a":1,"unknown":2}`} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("accepted invalid JSON %s", raw)
		}
	}
}

func TestValues(t *testing.T) {
	if _, err := Domain("127.0.0.1"); err == nil {
		t.Fatal("domain accepted IP")
	}
	for in, want := range map[string]string{"EXAMPLE.COM": "example.com", "2001:0db8::1": "2001:db8::1"} {
		v, err := Host(in)
		if err != nil {
			t.Fatal(err)
		}
		if v.String() != want {
			t.Errorf("got %q", v.String())
		}
	}
	v, err := URL("https://[2001:db8::1]:443")
	if err != nil || v.String() != "https://[2001:db8::1]:443/" {
		t.Fatalf("URL: %v %s", err, v.String())
	}
	if v.Type() != "url/v1" {
		t.Fatal(v.Type())
	}
}

func TestValidationAndOutputs(t *testing.T) {
	m := testManifest()
	if _, err := Compile(m); err != nil {
		t.Fatal(err)
	}
	bad := testManifest()
	bad.Parameters[0].Enum = nil
	if _, err := Compile(bad); err == nil {
		t.Fatal("empty enum accepted")
	}
	v, _ := Host("example.com")
	outs, err := ValidateOutputs(m, []NamedOutput{{Name: "host", Values: []Value{v, v}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 || len(outs[0].Values) != 1 {
		t.Fatal("outputs were not deduplicated")
	}
	if _, err := NormalizeParameter(Parameter{Name: "x", Kind: string(ParameterKindString)}, map[string]string{"x": ""}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatal("empty string accepted")
	}
}

func TestValidateOutputsAllowsEmptyOneAndMany(t *testing.T) {
	m := testManifest()
	m.Outputs = []Output{{Name: "single", Type: string(ValueTypeHost), Cardinality: string(CardinalityOne)}, {Name: "many", Type: string(ValueTypeHost), Cardinality: string(CardinalityMany)}}
	got, err := ValidateOutputs(m, []NamedOutput{{Name: "single"}, {Name: "many"}})
	if err != nil || len(got) != 2 || len(got[0].Values) != 0 || len(got[1].Values) != 0 {
		t.Fatalf("empty outputs: %#v %v", got, err)
	}
}

func TestDescriptorManifestIsDeeplyCloned(t *testing.T) {
	n := int64(1)
	max := int64(9)
	minItems := 2
	m := testManifest()
	m.Parameters = append(m.Parameters, Parameter{Name: "count", Kind: string(ParameterKindInteger), Minimum: &n, Maximum: &max}, Parameter{Name: "items", Kind: string(ParameterKindStringList), MinItems: &minItems})
	d, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	originalCanonical, originalDigest := d.CanonicalJSON(), d.Digest()
	returned := d.Manifest()
	*returned.Parameters[1].Minimum = 7
	*returned.Parameters[1].Maximum = 8
	*returned.Parameters[2].MinItems = 3
	if !bytes.Equal(originalCanonical, d.CanonicalJSON()) || originalDigest != d.Digest() {
		t.Fatal("manifest mutation changed descriptor")
	}
	if *d.Manifest().Parameters[1].Minimum != 1 {
		t.Fatal("descriptor manifest was shallow-copied")
	}
}

func TestEscapedQuoteDoesNotEndStringForSurrogateValidation(t *testing.T) {
	raw := `{"manifest_version":1,"capability":"portscan","contract_id":"vpt/portscan/v1","display":{"name":"quote \" here \ud800"},"inputs":[],"outputs":[],"parameters":[]}`
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("accepted unpaired surrogate after escaped quote")
	}
}

func TestCompileRejectsInvalidUTF8(t *testing.T) {
	m := testManifest()
	m.Display = &Display{Name: string([]byte{0xff})}
	if _, err := Compile(m); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestManifestValidationAndLimits(t *testing.T) {
	for _, capability := range []string{"subdomain", "portscan", "httpprobe", "vuln"} {
		m := testManifest()
		m.Capability = capability
		m.ContractID = "vpt/" + capability + "/v1"
		if _, err := Compile(m); err != nil {
			t.Errorf("canonical ID %s: %v", m.ContractID, err)
		}
	}

	cases := map[string]func(*Manifest){
		"unknown capability": func(m *Manifest) { m.Capability = "other" },
		"mismatched ID":      func(m *Manifest) { m.ContractID = "vpt/vuln/v1" },
		"invalid name":       func(m *Manifest) { m.Inputs[0].Name = "Target" },
		"duplicate type": func(m *Manifest) {
			m.Inputs[0].AcceptedTypes = []string{"host/v1", "host/v1"}
		},
		"invalid cardinality": func(m *Manifest) { m.Inputs[0].Cardinality = "some" },
		"duplicate enum": func(m *Manifest) {
			m.Parameters[0].Enum = []string{"fast", "fast"}
		},
		"empty enum": func(m *Manifest) { m.Parameters[0].Enum = nil },
		"negative bound": func(m *Manifest) {
			m.Parameters[0] = Parameter{Name: "value", Kind: "string", MinLength: intptr(-1)}
		},
		"reversed bounds": func(m *Manifest) {
			m.Parameters[0] = Parameter{Name: "value", Kind: "integer", Minimum: int64ptr(2), Maximum: int64ptr(1)}
		},
		"inapplicable bounds": func(m *Manifest) { m.Parameters[0].Minimum = int64ptr(1) },
		"too many inputs": func(m *Manifest) {
			m.Inputs = make([]Input, MaxInputs+1)
		},
		"missing outputs":    func(m *Manifest) { m.Outputs = nil },
		"missing parameters": func(m *Manifest) { m.Parameters = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testManifest()
			mutate(&m)
			if _, err := Compile(m); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}

	if _, err := Parse(bytes.Repeat([]byte(" "), CanonicalSizeLimit+1)); err == nil {
		t.Fatal("oversized raw manifest accepted")
	}
	huge := testManifest()
	huge.Parameters[0].Enum = []string{strings.Repeat("x", CanonicalSizeLimit)}
	huge.Parameters[0].Default = nil
	if _, err := Compile(huge); err == nil {
		t.Fatal("oversized canonical manifest accepted")
	}
}

func TestParameterNormalization(t *testing.T) {
	params := []Parameter{
		{Name: "mode", Kind: "enum", Enum: []string{"fast", "full"}, Default: strptr("fast")},
		{Name: "enabled", Kind: "boolean"},
		{Name: "count", Kind: "integer", Minimum: int64ptr(-10), Maximum: int64ptr(10)},
		{Name: "label", Kind: "string", MinLength: intptr(0), MaxLength: intptr(3)},
		{Name: "tags", Kind: "string_list", MinItems: intptr(0), MaxItems: intptr(3)},
		{Name: "ports", Kind: "port_set", Required: true},
	}
	m := Manifest{Parameters: params}
	in := map[string]string{"enabled": " TRUE ", "count": "+007", "label": "é", "tags": "one, two,one", "ports": " 080, 443, 8000-08002 "}
	got, err := NormalizeParameters(&m, in)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"mode": "fast", "enabled": "true", "count": "7", "label": "é", "tags": "one,two,one", "ports": "80,443,8000-8002"}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	if in["enabled"] != " TRUE " || in["ports"] != " 080, 443, 8000-08002 " {
		t.Fatal("input map was mutated")
	}
	for _, preset := range []string{"100", "1000", "full", "100-100"} {
		got, err := NormalizeParameter(Parameter{Name: "ports", Kind: "port_set"}, map[string]string{"ports": preset})
		if err != nil || got["ports"] != preset {
			t.Errorf("port set %q: %q %v", preset, got["ports"], err)
		}
	}
	invalidPorts := []string{"", "0", "65536", "443-80", "full,443", "80,,443"}
	for _, value := range invalidPorts {
		if _, err := NormalizeParameter(Parameter{Name: "ports", Kind: "port_set"}, map[string]string{"ports": value}); err == nil {
			t.Errorf("invalid port set %q accepted", value)
		}
	}
	if _, err := NormalizeParameters(&m, map[string]string{"unknown": "x"}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
	if _, err := NormalizeParameters(&m, map[string]string{}); err == nil {
		t.Fatal("required parameter omitted")
	}
	if got, err := NormalizeParameter(Parameter{Name: "x", Kind: "string", MinLength: intptr(0)}, map[string]string{"x": ""}); err != nil || got["x"] != "" {
		t.Fatalf("explicit empty string rejected: %v", err)
	}
	if got, err := NormalizeParameter(Parameter{Name: "x", Kind: "string_list", MinItems: intptr(0)}, map[string]string{"x": ""}); err != nil || got["x"] != "" {
		t.Fatalf("explicit empty list rejected: %v", err)
	}
}

func TestStringListItemsEnum(t *testing.T) {
	p := Parameter{Name: "methods", Kind: "string_list", ItemsEnum: []string{"GET", "POST"}}
	got, err := NormalizeParameter(p, map[string]string{"methods": "GET,POST"})
	if err != nil || got["methods"] != "GET,POST" {
		t.Fatalf("items enum normalization: %#v %v", got, err)
	}
	if _, err := NormalizeParameter(p, map[string]string{"methods": "GET,DELETE"}); err == nil {
		t.Fatal("unknown list item accepted")
	}
	for _, bad := range []Parameter{
		{Name: "methods", Kind: "string", ItemsEnum: []string{"GET"}},
		{Name: "methods", Kind: "string_list", ItemsEnum: []string{""}},
		{Name: "methods", Kind: "string_list", ItemsEnum: []string{"GET", "GET"}},
	} {
		m := testManifest()
		m.Parameters = []Parameter{bad}
		if _, err := Compile(m); err == nil {
			t.Fatalf("invalid items enum accepted: %#v", bad)
		}
	}
}

func TestTypedValueValidation(t *testing.T) {
	host, err := Host("::ffff:192.0.2.1")
	if err != nil || host.String() != "192.0.2.1" {
		t.Fatalf("mapped IPv4: %q %v", host.String(), err)
	}
	for _, value := range []string{"bad host", "-bad.example", "example.com.", "exa_mple.com", "fe80::1%eth0"} {
		if _, err := Host(value); err == nil {
			t.Errorf("invalid host %q accepted", value)
		}
	}
	validURLs := map[string]string{
		"HTTP://EXAMPLE.COM":            "http://example.com/",
		"https://[2001:db8::1]":         "https://[2001:db8::1]/",
		"https://example.com:0443":      "https://example.com:443/",
		"https://example.com/%7e?a=%7E": "https://example.com/~?a=~",
	}
	for input, want := range validURLs {
		value, err := URL(input)
		if err != nil || value.String() != want {
			t.Errorf("URL %q = %q, %v; want %q", input, value.String(), err, want)
		}
	}
	for _, value := range []string{"ftp://example.com", "https://user@example.com", "https://example.com/#fragment", "https://example.com:0", "https://bad host/", "https://example.com/\u00a0", "http://[fe80::1%25eth0]/"} {
		if _, err := URL(value); err == nil {
			t.Errorf("invalid URL %q accepted", value)
		}
	}
}

func TestOutputValidationFailures(t *testing.T) {
	m := testManifest()
	m.Outputs = []Output{{Name: "first", Type: "host/v1", Cardinality: "many"}, {Name: "second", Type: "host/v1", Cardinality: "one"}}
	a, _ := Host("a.example.com")
	b, _ := Host("b.example.com")
	got, err := ValidateOutputs(m, []NamedOutput{{Name: "second", Values: []Value{a}}, {Name: "first", Values: []Value{b, b, a}}})
	if err != nil || got[0].Name != "first" || len(got[0].Values) != 2 {
		t.Fatalf("ordered dedupe failed: %#v %v", got, err)
	}
	badCases := []struct {
		name string
		outs []NamedOutput
	}{
		{"missing", []NamedOutput{{Name: "first"}}},
		{"duplicate", []NamedOutput{{Name: "first"}, {Name: "first"}, {Name: "second"}}},
		{"undeclared", []NamedOutput{{Name: "first"}, {Name: "other"}}},
		{"wrong type", []NamedOutput{{Name: "first"}, {Name: "second", Values: []Value{mustDomain(t, "example.com")}}}},
		{"one cardinality", []NamedOutput{{Name: "first"}, {Name: "second", Values: []Value{a, b}}}},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateOutputs(m, tc.outs); err == nil {
				t.Fatal("invalid outputs accepted")
			}
		})
	}
}

func mustDomain(t *testing.T, value string) Value {
	t.Helper()
	v, err := Domain(value)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestStrictNestedDuplicateAndSurrogatePair(t *testing.T) {
	base := `{"manifest_version":1,"capability":"portscan","contract_id":"vpt/portscan/v1","display":%s,"inputs":[{"name":"target","accepted_types":["host/v1"],"cardinality":"one"}],"outputs":[],"parameters":[]}`
	if _, err := Parse([]byte(fmt.Sprintf(base, `{"name":"a","name":"b"}`))); err == nil {
		t.Fatal("nested duplicate key accepted")
	}
	if _, err := Parse([]byte(fmt.Sprintf(base, `{"name":"\ud83d\ude00"}`))); err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
}
