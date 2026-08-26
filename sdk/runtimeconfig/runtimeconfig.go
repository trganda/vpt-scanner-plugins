// Package runtimeconfig defines the canonical plugin runtime configuration.
package runtimeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

const Version = 1
const maxParameters = 64
const maxJSONSize = 256 * 1024

type Scope string

const (
	ScopePlugin Scope = "plugin"
	ScopeWorker Scope = "worker"
)

type Parameter struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Scope     Scope    `json:"scope"`
	Required  bool     `json:"required"`
	Default   *string  `json:"default,omitempty"`
	Enum      []string `json:"enum,omitempty"`
	Minimum   *int64   `json:"minimum,omitempty"`
	Maximum   *int64   `json:"maximum,omitempty"`
	MinItems  *int     `json:"min_items,omitempty"`
	MaxItems  *int     `json:"max_items,omitempty"`
	MinLength *int     `json:"min_length,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
	ItemsEnum []string `json:"items_enum,omitempty"`
}
type Manifest struct {
	ManifestVersion int         `json:"manifest_version"`
	Capability      string      `json:"capability"`
	Parameters      []Parameter `json:"parameters"`
}
type Descriptor struct {
	manifest  Manifest
	canonical []byte
	sha       string
}

func (d *Descriptor) Manifest() Manifest    { return cloneManifest(d.manifest) }
func (d *Descriptor) CanonicalJSON() []byte { return append([]byte(nil), d.canonical...) }
func (d *Descriptor) SHA256() string        { return d.sha }

func Compile(m Manifest) (*Descriptor, error) {
	m = cloneManifest(m)
	if m.ManifestVersion != Version || m.Capability == "" || len(m.Parameters) == 0 || len(m.Parameters) > maxParameters {
		return nil, fmt.Errorf("invalid runtime manifest identity")
	}
	seen := map[string]bool{}
	for i, p := range m.Parameters {
		if p.Name == "" || seen[p.Name] {
			return nil, fmt.Errorf("invalid or duplicate parameter")
		}
		seen[p.Name] = true
		if p.Scope != ScopePlugin && p.Scope != ScopeWorker {
			return nil, fmt.Errorf("invalid parameter scope")
		}
		if p.Kind != string(contract.ParameterKindBoolean) && p.Kind != string(contract.ParameterKindInteger) && p.Kind != string(contract.ParameterKindString) && p.Kind != string(contract.ParameterKindStringList) && p.Kind != string(contract.ParameterKindEnum) {
			return nil, fmt.Errorf("invalid parameter kind")
		}
		if !utf8.ValidString(p.Name) || !utf8.ValidString(p.Kind) {
			return nil, fmt.Errorf("invalid UTF-8")
		}
		cm := contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: m.Capability, ContractID: "vpt/" + m.Capability + "/v1", Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{"host/v1"}, Cardinality: "one"}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: p.Name, Kind: p.Kind, Required: p.Required, Default: p.Default, Enum: p.Enum, Minimum: p.Minimum, Maximum: p.Maximum, MinItems: p.MinItems, MaxItems: p.MaxItems, MinLength: p.MinLength, MaxLength: p.MaxLength, ItemsEnum: p.ItemsEnum}}}
		if _, err := contract.Compile(cm); err != nil {
			return nil, err
		}
		if p.Default != nil {
			n, err := contract.NormalizeParameter(cm.Parameters[0], map[string]string{p.Name: *p.Default})
			if err != nil {
				return nil, err
			}
			v := n[p.Name]
			p.Default = &v
		}
		m.Parameters[i] = p
	}
	b, err := canonical(m)
	if err != nil {
		return nil, err
	}
	if len(b) > maxJSONSize {
		return nil, fmt.Errorf("runtime manifest too large")
	}
	h := sha256.Sum256(b)
	return &Descriptor{manifest: m, canonical: b, sha: "sha256:" + hex.EncodeToString(h[:])}, nil
}
func Parse(raw []byte) (*Descriptor, error) {
	if len(raw) > maxJSONSize || !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid or oversized runtime manifest")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err := parseValue(d, &value); err != nil {
		return nil, err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	if value == nil {
		return nil, fmt.Errorf("runtime manifest is null")
	}
	b, err := canonical(value)
	if err != nil {
		return nil, err
	}
	var m Manifest
	md := json.NewDecoder(bytes.NewReader(b))
	md.DisallowUnknownFields()
	if err := md.Decode(&m); err != nil {
		return nil, err
	}
	var extra any
	if err := md.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return Compile(m)
}

// NormalizeValues validates a strict values object, applies descriptor defaults,
// and partitions values by their execution scope.
func (d *Descriptor) NormalizeValues(in map[string]string) (plugin, worker map[string]string, err error) {
	plugin, worker = map[string]string{}, map[string]string{}
	known := make(map[string]Parameter, len(d.manifest.Parameters))
	for _, p := range d.manifest.Parameters {
		known[p.Name] = p
	}
	for k := range in {
		if _, ok := known[k]; !ok {
			return nil, nil, fmt.Errorf("unknown runtime parameter %q", k)
		}
	}
	for _, p := range d.manifest.Parameters {
		v, ok := in[p.Name]
		if !ok {
			if p.Default != nil {
				v, ok = *p.Default, true
			} else if p.Required {
				return nil, nil, fmt.Errorf("missing runtime parameter %q", p.Name)
			}
		}
		if !ok {
			continue
		}
		cm := contract.Parameter{Name: p.Name, Kind: p.Kind, Required: p.Required, Default: p.Default, Enum: p.Enum, Minimum: p.Minimum, Maximum: p.Maximum, MinLength: p.MinLength, MaxLength: p.MaxLength, MinItems: p.MinItems, MaxItems: p.MaxItems, ItemsEnum: p.ItemsEnum}
		n, e := contract.NormalizeParameter(cm, map[string]string{p.Name: v})
		if e != nil {
			return nil, nil, e
		}
		if p.Scope == ScopePlugin {
			plugin[p.Name] = n[p.Name]
		} else {
			worker[p.Name] = n[p.Name]
		}
	}
	return plugin, worker, nil
}

// ParseValues decodes a strict JSON object whose values are strings.
func (d *Descriptor) ParseValues(raw []byte) (map[string]string, map[string]string, error) {
	if len(raw) > maxJSONSize || !utf8.Valid(raw) {
		return nil, nil, fmt.Errorf("invalid or oversized runtime values")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return nil, nil, fmt.Errorf("runtime values must be an object")
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for dec.More() {
		k, e := dec.Token()
		if e != nil {
			return nil, nil, e
		}
		key := k.(string)
		if seen[key] {
			return nil, nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var s string
		if e = dec.Decode(&s); e != nil {
			return nil, nil, fmt.Errorf("runtime value %q must be a string", key)
		}
		values[key] = s
	}
	if _, err = dec.Token(); err != nil {
		return nil, nil, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return nil, nil, fmt.Errorf("trailing JSON")
	}
	return d.NormalizeValues(values)
}

func parseValue(d *json.Decoder, out *any) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key := k.(string)
				if seen[key] {
					return fmt.Errorf("duplicate key %q", key)
				}
				seen[key] = true
				var v any
				if e = parseValue(d, &v); e != nil {
					return e
				}
				m[key] = v
			}
			if _, err = d.Token(); err != nil {
				return err
			}
			*out = m
			return nil
		case '[':
			a := []any{}
			for d.More() {
				var v any
				if err = parseValue(d, &v); err != nil {
					return err
				}
				a = append(a, v)
			}
			if _, err = d.Token(); err != nil {
				return err
			}
			*out = a
			return nil
		}
		return fmt.Errorf("invalid JSON delimiter")
	}
	if t == nil {
		return fmt.Errorf("null is not allowed")
	}
	*out = t
	return nil
}
func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var x any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&x); e != nil {
		return nil, e
	}
	return canon(x)
}
func canon(v any) ([]byte, error) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b bytes.Buffer
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			q, _ := json.Marshal(k)
			b.Write(q)
			b.WriteByte(':')
			z, e := canon(x[k])
			if e != nil {
				return nil, e
			}
			b.Write(z)
		}
		b.WriteByte('}')
		return b.Bytes(), nil
	case []any:
		var b bytes.Buffer
		b.WriteByte('[')
		for i, z := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			q, e := canon(z)
			if e != nil {
				return nil, e
			}
			b.Write(q)
		}
		b.WriteByte(']')
		return b.Bytes(), nil
	default:
		return json.Marshal(x)
	}
}

func cloneManifest(m Manifest) Manifest {
	o := m
	o.Parameters = append([]Parameter(nil), m.Parameters...)
	for i, p := range o.Parameters {
		o.Parameters[i].Enum = append([]string(nil), p.Enum...)
		o.Parameters[i].ItemsEnum = append([]string(nil), p.ItemsEnum...)
		if p.Default != nil {
			x := *p.Default
			o.Parameters[i].Default = &x
		}
		if p.Minimum != nil {
			x := *p.Minimum
			o.Parameters[i].Minimum = &x
		}
		if p.Maximum != nil {
			x := *p.Maximum
			o.Parameters[i].Maximum = &x
		}
		if p.MinItems != nil {
			x := *p.MinItems
			o.Parameters[i].MinItems = &x
		}
		if p.MaxItems != nil {
			x := *p.MaxItems
			o.Parameters[i].MaxItems = &x
		}
		if p.MinLength != nil {
			x := *p.MinLength
			o.Parameters[i].MinLength = &x
		}
		if p.MaxLength != nil {
			x := *p.MaxLength
			o.Parameters[i].MaxLength = &x
		}
	}
	return o
}
