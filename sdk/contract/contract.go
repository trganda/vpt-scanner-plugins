// Package contract defines the versioned scanner capability contract.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ProtocolVersion is the additive SDK wire protocol version. It remains 1 so
// contract-aware plugins can roll out alongside existing hosts and plugins.
const ProtocolVersion uint32 = 1

// ManifestVersion is the supported manifest schema version.
const ManifestVersion = 1

// CanonicalSizeLimit is the maximum raw or canonical manifest size.
const CanonicalSizeLimit = 256 * 1024

// Manifest limits bound descriptor resource usage.
const MaxInputs, MaxOutputs, MaxParameters = 32, 32, 64
const MaxDisplayName, MaxDisplayDescription = 128, 1024

// Capability identifies a scanner capability.
type Capability string

const (
	CapabilitySubdomain Capability = "subdomain"
	CapabilityPortscan  Capability = "portscan"
	CapabilityHTTPProbe Capability = "httpprobe"
	CapabilityVuln      Capability = "vuln"
	CapabilityKatana    Capability = "katana"
	CapabilityCloudlist Capability = "cloudlist"
)

// ValueType identifies a typed contract value.
type ValueType string

const (
	ValueTypeDomain ValueType = "domain/v1"
	ValueTypeHost   ValueType = "host/v1"
	ValueTypeURL    ValueType = "url/v1"
)

// Cardinality describes whether a field accepts one or many values.
type Cardinality string

const (
	CardinalityOne  Cardinality = "one"
	CardinalityMany Cardinality = "many"
)

// ParameterKind identifies parameter normalization rules.
type ParameterKind string

const (
	ParameterKindEnum       ParameterKind = "enum"
	ParameterKindBoolean    ParameterKind = "boolean"
	ParameterKindInteger    ParameterKind = "integer"
	ParameterKindString     ParameterKind = "string"
	ParameterKindStringList ParameterKind = "string_list"
	ParameterKindPortSet    ParameterKind = "port_set"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var knownCapabilities = []Capability{
	CapabilitySubdomain,
	CapabilityPortscan,
	CapabilityHTTPProbe,
	CapabilityVuln,
	CapabilityKatana,
	CapabilityCloudlist,
}

// Capabilities returns all capabilities supported by this SDK in stable order.
// The returned slice is a copy and may be safely changed by the caller.
func Capabilities() []Capability { return append([]Capability(nil), knownCapabilities...) }

// IsCapability reports whether value is a capability supported by this SDK.
func IsCapability(value string) bool {
	for _, capability := range knownCapabilities {
		if string(capability) == value {
			return true
		}
	}
	return false
}

var types = map[string]bool{"domain/v1": true, "host/v1": true, "url/v1": true}

// Manifest describes one scanner capability's versioned inputs, outputs, and parameters.
type Manifest struct {
	ManifestVersion int         `json:"manifest_version"`
	Capability      string      `json:"capability"`
	ContractID      string      `json:"contract_id"`
	Display         *Display    `json:"display,omitempty"`
	Inputs          []Input     `json:"inputs"`
	Outputs         []Output    `json:"outputs"`
	Parameters      []Parameter `json:"parameters"`
}

// Display contains presentation-only manifest metadata.
type Display struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// Input declares one named capability input.
type Input struct {
	Name          string   `json:"name"`
	AcceptedTypes []string `json:"accepted_types"`
	Cardinality   string   `json:"cardinality"`
}

// Output declares one named typed capability output.
type Output struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Cardinality string `json:"cardinality"`
}

// Parameter declares one governed runtime parameter.
type Parameter struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Required  bool     `json:"required"`
	Default   *string  `json:"default,omitempty"`
	Enum      []string `json:"enum,omitempty"`
	Minimum   *int64   `json:"minimum,omitempty"`
	Maximum   *int64   `json:"maximum,omitempty"`
	MinLength *int     `json:"min_length,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
	MinItems  *int     `json:"min_items,omitempty"`
	MaxItems  *int     `json:"max_items,omitempty"`
}
type semanticManifest struct {
	ManifestVersion int         `json:"manifest_version"`
	Capability      string      `json:"capability"`
	ContractID      string      `json:"contract_id"`
	Inputs          []Input     `json:"inputs"`
	Outputs         []Output    `json:"outputs"`
	Parameters      []Parameter `json:"parameters"`
}

// Descriptor is an immutable validated manifest and its canonical identities.
type Descriptor struct {
	manifest                       Manifest
	canonical, semantic            []byte
	contractDigest, manifestSHA256 string
}

// Manifest returns a deep copy of the normalized manifest.
func (d *Descriptor) Manifest() Manifest { return cloneManifest(d.manifest) }

// CanonicalJSON returns the complete canonical manifest bytes.
func (d *Descriptor) CanonicalJSON() []byte { return append([]byte(nil), d.canonical...) }

// SemanticJSON returns the canonical behavior-bearing manifest projection.
func (d *Descriptor) SemanticJSON() []byte { return append([]byte(nil), d.semantic...) }

// Digest returns the semantic contract digest.
func (d *Descriptor) Digest() string { return d.contractDigest }

// ManifestDigest returns the digest of the complete canonical manifest.
func (d *Descriptor) ManifestDigest() string { return d.manifestSHA256 }

// Parse strictly decodes, validates, normalizes, and compiles a JSON manifest.
func Parse(raw []byte) (*Descriptor, error) {
	if len(raw) > CanonicalSizeLimit || !utf8.Valid(raw) {
		return nil, errors.New("manifest is invalid or too large")
	}
	if err := validateJSONStringEscapes(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := decodeStrict(dec, &v); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("manifest root is null")
	}
	b, err := canonical(v)
	if err != nil {
		return nil, err
	}
	var m Manifest
	sd := json.NewDecoder(bytes.NewReader(b))
	sd.DisallowUnknownFields()
	if err = sd.Decode(&m); err != nil {
		return nil, err
	}
	if err = ensureEOF(sd); err != nil {
		return nil, err
	}
	return Compile(m)
}

// Compile validates, normalizes, and canonicalizes a programmatic manifest.
func Compile(in Manifest) (*Descriptor, error) {
	m := cloneManifest(in)
	if err := validateUTF8(m); err != nil {
		return nil, err
	}
	if m.Inputs == nil || m.Outputs == nil || m.Parameters == nil {
		return nil, errors.New("manifest inputs, outputs, and parameters are required")
	}
	if err := validate(&m); err != nil {
		return nil, err
	}
	for i := range m.Parameters {
		if m.Parameters[i].Default != nil {
			n, e := NormalizeParameter(m.Parameters[i], map[string]string{m.Parameters[i].Name: *m.Parameters[i].Default})
			if e != nil {
				return nil, e
			}
			x := n[m.Parameters[i].Name]
			m.Parameters[i].Default = &x
		}
	}
	full, err := canonicalDocument(m)
	if err != nil {
		return nil, err
	}
	semm := semanticManifest{ManifestVersion: m.ManifestVersion, Capability: m.Capability, ContractID: m.ContractID, Inputs: m.Inputs, Outputs: m.Outputs, Parameters: m.Parameters}
	sem, err := canonicalDocument(semm)
	if err != nil {
		return nil, err
	}
	if len(full) > CanonicalSizeLimit || len(sem) > CanonicalSizeLimit {
		return nil, errors.New("canonical manifest too large")
	}
	return &Descriptor{manifest: m, canonical: full, semantic: sem, contractDigest: digest(sem), manifestSHA256: digest(full)}, nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// ValidDigest reports whether a digest uses the canonical SHA-256 wire form.
func ValidDigest(value string) bool { return digestRE.MatchString(value) }

func canonicalDocument(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&decoded); err != nil {
		return nil, err
	}
	return canonical(decoded)
}

func decodeStrict(d *json.Decoder, out *any) error {
	if err := parseValue(d, out); err != nil {
		return err
	}
	var x any
	err := d.Decode(&x)
	if err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func ensureEOF(d *json.Decoder) error {
	var x any
	if err := d.Decode(&x); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func parseValue(d *json.Decoder, out *any) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	switch x := t.(type) {
	case json.Delim:
		if x == '{' {
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
			if _, e = d.Token(); e != nil {
				return e
			}
			*out = m
			return nil
		}
		if x == '[' {
			var a []any
			for d.More() {
				var v any
				if e = parseValue(d, &v); e != nil {
					return e
				}
				a = append(a, v)
			}
			if _, e = d.Token(); e != nil {
				return e
			}
			*out = a
			return nil
		}
		return errors.New("invalid JSON delimiter")
	default:
		if x == nil {
			return errors.New("null is not allowed")
		}
		*out = x
		return nil
	}
}
func canonical(v any) ([]byte, error) {
	switch x := v.(type) {
	case Manifest, *Manifest:
		b, e := json.Marshal(x)
		if e != nil {
			return nil, e
		}
		var y any
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if e = d.Decode(&y); e != nil {
			return nil, e
		}
		return canonical(y)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare([]byte(keys[i]), []byte(keys[j])) < 0 })
		var b bytes.Buffer
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			q, _ := canonicalString(k)
			b.Write(q)
			b.WriteByte(':')
			z, e := canonical(x[k])
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
			q, e := canonical(z)
			if e != nil {
				return nil, e
			}
			b.Write(q)
		}
		b.WriteByte(']')
		return b.Bytes(), nil
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return nil, errors.New("invalid number")
		}
		if _, e := strconv.ParseInt(string(x), 10, 64); e != nil {
			return nil, e
		}
		return []byte(x), nil
	default:
		b := &bytes.Buffer{}
		e := json.NewEncoder(b)
		e.SetEscapeHTML(false)
		if err := e.Encode(x); err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
	}
}

func canonicalString(s string) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

func validate(m *Manifest) error {
	if m.ManifestVersion != ManifestVersion || !IsCapability(m.Capability) || m.ContractID != "vpt/"+m.Capability+"/v1" || len(m.Inputs) == 0 {
		return errors.New("invalid manifest identity")
	}
	if len(m.Inputs) > MaxInputs || len(m.Outputs) > MaxOutputs || len(m.Parameters) > MaxParameters {
		return errors.New("manifest limits exceeded")
	}
	if m.Display != nil && (utf8.RuneCountInString(m.Display.Name) > MaxDisplayName || utf8.RuneCountInString(m.Display.Description) > MaxDisplayDescription) {
		return errors.New("display too long")
	}
	names := map[string]bool{}
	for _, i := range m.Inputs {
		if err := validName(i.Name, &names); err != nil {
			return err
		}
		if len(i.AcceptedTypes) == 0 || (i.Cardinality != "one" && i.Cardinality != "many") {
			return errors.New("invalid input")
		}
		seen := map[string]bool{}
		for _, t := range i.AcceptedTypes {
			if !types[t] || seen[t] {
				return errors.New("invalid input type")
			}
			seen[t] = true
		}
	}
	names = map[string]bool{}
	for _, o := range m.Outputs {
		if err := validName(o.Name, &names); err != nil {
			return err
		}
		if !types[o.Type] || (o.Cardinality != "one" && o.Cardinality != "many") {
			return errors.New("invalid output")
		}
	}
	names = map[string]bool{}
	for _, p := range m.Parameters {
		if err := validName(p.Name, &names); err != nil {
			return err
		}
		if !validKind(p.Kind) {
			return errors.New("invalid parameter kind")
		}
		if p.Kind == "enum" {
			if len(p.Enum) == 0 {
				return errors.New("empty enum")
			}
			seen := map[string]bool{}
			for _, x := range p.Enum {
				if seen[x] {
					return errors.New("duplicate enum")
				}
				seen[x] = true
			}
		}
		for _, x := range []*int{p.MinLength, p.MaxLength, p.MinItems, p.MaxItems} {
			if x != nil && *x < 0 {
				return errors.New("negative bound")
			}
		}
		if p.Minimum != nil && p.Maximum != nil && *p.Minimum > *p.Maximum || p.MinLength != nil && p.MaxLength != nil && *p.MinLength > *p.MaxLength || p.MinItems != nil && p.MaxItems != nil && *p.MinItems > *p.MaxItems {
			return errors.New("invalid bounds")
		}
		if p.Kind != "integer" && (p.Minimum != nil || p.Maximum != nil) || p.Kind != "string" && (p.MinLength != nil || p.MaxLength != nil) || p.Kind != "string_list" && (p.MinItems != nil || p.MaxItems != nil) || p.Kind != "enum" && len(p.Enum) > 0 {
			return errors.New("inapplicable bounds")
		}
	}
	return nil
}
func validName(s string, seen *map[string]bool) error {
	if !nameRE.MatchString(s) || (*seen)[s] {
		return errors.New("invalid or duplicate name")
	}
	(*seen)[s] = true
	return nil
}
func validKind(s string) bool {
	switch s {
	case "enum", "boolean", "integer", "string", "string_list", "port_set":
		return true
	}
	return false
}

// NormalizeParameters validates parameters and returns a new canonical wire map.
func NormalizeParameters(m *Manifest, in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	known := map[string]Parameter{}
	for _, p := range m.Parameters {
		known[p.Name] = p
	}
	for k := range in {
		if _, ok := known[k]; !ok {
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}
	for _, p := range m.Parameters {
		v, ok := in[p.Name]
		if !ok {
			if p.Default != nil {
				v = *p.Default
				ok = true
			} else if p.Required {
				return nil, fmt.Errorf("missing parameter %q", p.Name)
			} else {
				continue
			}
		}
		n, e := NormalizeParameter(p, map[string]string{p.Name: v})
		if e != nil {
			return nil, e
		}
		out[p.Name] = n[p.Name]
	}
	return out, nil
}

// NormalizeParameter canonicalizes one parameter value without mutating the input map.
func NormalizeParameter(p Parameter, in map[string]string) (map[string]string, error) {
	v, ok := in[p.Name]
	if !ok {
		return map[string]string{}, nil
	}
	switch p.Kind {
	case "boolean":
		v = strings.TrimSpace(v)
		if !strings.EqualFold(v, "true") && !strings.EqualFold(v, "false") {
			return nil, errors.New("invalid boolean")
		}
		v = strings.ToLower(v)
	case "integer":
		v = strings.TrimSpace(v)
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || (p.Minimum != nil && n < *p.Minimum) || (p.Maximum != nil && n > *p.Maximum) {
			return nil, errors.New("invalid integer")
		}
		v = strconv.FormatInt(n, 10)
	case "enum":
		found := false
		for _, x := range p.Enum {
			if v == x {
				found = true
			}
		}
		if !found {
			return nil, errors.New("invalid enum")
		}
	case "string":
		n := utf8.RuneCountInString(v)
		if v == "" && p.MinLength == nil {
			return nil, errors.New("empty string")
		}
		if (p.MinLength != nil && n < *p.MinLength) || (p.MaxLength != nil && n > *p.MaxLength) {
			return nil, errors.New("invalid string length")
		}
	case "string_list":
		v = strings.TrimSpace(v)
		if v == "" {
			if p.MinItems == nil || *p.MinItems > 0 {
				return nil, errors.New("empty list")
			}
			return map[string]string{p.Name: ""}, nil
		}
		parts := strings.Split(v, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
			if parts[i] == "" {
				return nil, errors.New("empty list item")
			}
		}
		if (p.MinItems != nil && len(parts) < *p.MinItems) || (p.MaxItems != nil && len(parts) > *p.MaxItems) {
			return nil, errors.New("invalid list length")
		}
		v = strings.Join(parts, ",")
	case "port_set":
		v = strings.TrimSpace(v)
		if v == "100" || v == "1000" || v == "full" {
			return map[string]string{p.Name: v}, nil
		}
		var norm []string
		for _, x := range strings.Split(v, ",") {
			q := strings.Split(strings.TrimSpace(x), "-")
			if len(q) > 2 || q[0] == "" {
				return nil, errors.New("invalid port set")
			}
			for i := range q {
				n, e := strconv.Atoi(strings.TrimSpace(q[i]))
				if e != nil || n < 1 || n > 65535 {
					return nil, errors.New("invalid port")
				}
				q[i] = strconv.Itoa(n)
			}
			if len(q) == 2 && atoi(q[0]) > atoi(q[1]) {
				return nil, errors.New("invalid port range")
			}
			norm = append(norm, strings.Join(q, "-"))
		}
		v = strings.Join(norm, ",")
	default:
		return nil, errors.New("invalid kind")
	}
	return map[string]string{p.Name: v}, nil
}
func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// Value is a canonical closed-set contract value.
type Value struct{ typ, value string }

// Domain constructs a canonical domain/v1 value.
func Domain(s string) (Value, error) { return makeDNS(s, false) }

// Host constructs a canonical host/v1 DNS or IP value.
func Host(s string) (Value, error) {
	if hasBad(s) {
		return Value{}, errors.New("invalid host")
	}
	if a, e := netip.ParseAddr(s); e == nil {
		if a.Zone() != "" {
			return Value{}, errors.New("scoped IP addresses are not supported")
		}
		return Value{"host/v1", a.Unmap().String()}, nil
	}
	return makeDNS(s, true)
}

// NewDomain constructs a canonical domain/v1 value.
func NewDomain(s string) (Value, error) { return Domain(s) }

// NewHost constructs a canonical host/v1 value.
func NewHost(s string) (Value, error) { return Host(s) }

// NewURL constructs a canonical url/v1 value.
func NewURL(s string) (Value, error) { return URL(s) }

// URL constructs a canonical absolute HTTP or HTTPS url/v1 value.
func URL(s string) (Value, error) {
	if hasBad(s) {
		return Value{}, errors.New("invalid URL")
	}
	u, e := url.Parse(s)
	if e != nil || !u.IsAbs() || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) || u.User != nil || u.Fragment != "" || u.Host == "" || u.Opaque != "" || u.RawQuery != "" && strings.ContainsAny(u.RawQuery, "\r\n") {
		return Value{}, errors.New("invalid URL")
	}
	h := u.Hostname()
	if a, e := netip.ParseAddr(h); e == nil {
		if a.Zone() != "" {
			return Value{}, errors.New("scoped IP addresses are not supported")
		}
		h = a.Unmap().String()
	} else {
		d, e := makeDNS(h, true)
		if e != nil {
			return Value{}, e
		}
		h = d.value
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return Value{}, errors.New("invalid URL port")
		}
		h = net.JoinHostPort(h, strconv.Itoa(n))
	} else if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	path, err := normalizePercentEncoding(u.EscapedPath())
	if err != nil {
		return Value{}, errors.New("invalid URL path")
	}
	if path == "" {
		path = "/"
	}
	query, err := normalizePercentEncoding(u.RawQuery)
	if err != nil {
		return Value{}, errors.New("invalid URL query")
	}
	canonical := strings.ToLower(u.Scheme) + "://" + h + path
	if u.ForceQuery || u.RawQuery != "" {
		canonical += "?" + query
	}
	return Value{"url/v1", canonical}, nil
}
func hasBad(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
}

func normalizePercentEncoding(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("incomplete percent escape")
		}
		value, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", err
		}
		b := byte(value)
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b)) {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteString(strings.ToUpper(s[i+1 : i+3]))
		}
		i += 2
	}
	return out.String(), nil
}
func makeDNS(s string, host bool) (Value, error) {
	if hasBad(s) || len(s) > 253 || s == "" || strings.HasSuffix(s, ".") {
		return Value{}, errors.New("invalid DNS name")
	}
	s = strings.ToLower(s)
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return Value{}, errors.New("invalid DNS label")
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return Value{}, errors.New("invalid DNS label")
			}
		}
	}
	if !host && net.ParseIP(s) != nil {
		return Value{}, errors.New("domain cannot be IP")
	}
	typ := "domain/v1"
	if host {
		typ = "host/v1"
	}
	return Value{typ, s}, nil
}

// String returns the canonical wire value.
func (v Value) String() string { return v.value }

// Type returns the value's contract type ID.
func (v Value) Type() string { return v.typ }

// Domain returns the domain value when this is domain/v1.
func (v Value) Domain() (string, bool) { return v.value, v.typ == "domain/v1" }

// Host returns the host value when this is host/v1.
func (v Value) Host() (string, bool) { return v.value, v.typ == "host/v1" }

// URL returns the URL value when this is url/v1.
func (v Value) URL() (string, bool) { return v.value, v.typ == "url/v1" }

// NamedOutput contains the typed values emitted for one declared output.
type NamedOutput struct {
	Name   string
	Values []Value
}

// ValidateOutputs validates, deduplicates, and orders outputs by their declarations.
func ValidateOutputs(m Manifest, outs []NamedOutput) ([]NamedOutput, error) {
	decl := map[string]Output{}
	for _, o := range m.Outputs {
		decl[o.Name] = o
	}
	seen := map[string]bool{}
	out := []NamedOutput{}
	for _, x := range outs {
		o, ok := decl[x.Name]
		if !ok || seen[x.Name] {
			return nil, errors.New("invalid output")
		}
		seen[x.Name] = true
		ded := []Value{}
		for _, v := range x.Values {
			if v.typ != o.Type || !validValue(v) {
				return nil, errors.New("output type")
			}
			found := false
			for _, d := range ded {
				if d.typ == v.typ && d.value == v.value {
					found = true
				}
			}
			if !found {
				ded = append(ded, v)
			}
		}
		if o.Cardinality == "one" && len(ded) > 1 {
			return nil, errors.New("output cardinality")
		}
		out = append(out, NamedOutput{x.Name, ded})
	}
	if len(seen) != len(decl) {
		return nil, errors.New("missing output")
	}
	sort.SliceStable(out, func(i, j int) bool { return outputIndex(m.Outputs, out[i].Name) < outputIndex(m.Outputs, out[j].Name) })
	return out, nil
}
func outputIndex(a []Output, n string) int {
	for i, x := range a {
		if x.Name == n {
			return i
		}
	}
	return len(a)
}
func validValue(v Value) bool { return types[v.typ] && v.value != "" }
func cloneManifest(m Manifest) Manifest {
	o := m
	if m.Inputs != nil {
		o.Inputs = append([]Input{}, m.Inputs...)
	}
	if m.Outputs != nil {
		o.Outputs = append([]Output{}, m.Outputs...)
	}
	if m.Parameters != nil {
		o.Parameters = append([]Parameter{}, m.Parameters...)
	}
	for i := range o.Inputs {
		if m.Inputs[i].AcceptedTypes != nil {
			o.Inputs[i].AcceptedTypes = append([]string{}, m.Inputs[i].AcceptedTypes...)
		}
	}
	for i := range o.Parameters {
		if m.Parameters[i].Enum != nil {
			o.Parameters[i].Enum = append([]string{}, m.Parameters[i].Enum...)
		}
		if m.Parameters[i].Default != nil {
			x := *m.Parameters[i].Default
			o.Parameters[i].Default = &x
		}
		if m.Parameters[i].Minimum != nil {
			x := *m.Parameters[i].Minimum
			o.Parameters[i].Minimum = &x
		}
		if m.Parameters[i].Maximum != nil {
			x := *m.Parameters[i].Maximum
			o.Parameters[i].Maximum = &x
		}
		if m.Parameters[i].MinLength != nil {
			x := *m.Parameters[i].MinLength
			o.Parameters[i].MinLength = &x
		}
		if m.Parameters[i].MaxLength != nil {
			x := *m.Parameters[i].MaxLength
			o.Parameters[i].MaxLength = &x
		}
		if m.Parameters[i].MinItems != nil {
			x := *m.Parameters[i].MinItems
			o.Parameters[i].MinItems = &x
		}
		if m.Parameters[i].MaxItems != nil {
			x := *m.Parameters[i].MaxItems
			o.Parameters[i].MaxItems = &x
		}
	}
	if m.Display != nil {
		x := *m.Display
		o.Display = &x
	}
	return o
}

// validateJSONStringEscapes rejects JSON's otherwise silently repaired unpaired surrogates.
func validateJSONStringEscapes(b []byte) error {
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		for i++; i < len(b); i++ {
			if b[i] == '"' {
				break
			}
			if b[i] != '\\' {
				continue
			}
			if i+1 >= len(b) {
				return errors.New("invalid escape")
			}
			if b[i+1] != 'u' {
				i++
				continue
			}
			if i+5 >= len(b) {
				return errors.New("invalid unicode escape")
			}
			n, err := strconv.ParseUint(string(b[i+2:i+6]), 16, 16)
			if err != nil {
				return err
			}
			if n >= 0xdc00 && n <= 0xdfff {
				return errors.New("unpaired surrogate")
			}
			if n >= 0xd800 && n <= 0xdbff {
				if i+11 >= len(b) || b[i+6] != '\\' || b[i+7] != 'u' {
					return errors.New("unpaired surrogate")
				}
				q, err := strconv.ParseUint(string(b[i+8:i+12]), 16, 16)
				if err != nil || q < 0xdc00 || q > 0xdfff {
					return errors.New("unpaired surrogate")
				}
				i += 6
			}
			i += 5
		}
	}
	return nil
}

func validateUTF8(m Manifest) error {
	check := func(s string) error {
		if !utf8.ValidString(s) {
			return errors.New("manifest contains invalid UTF-8")
		}
		return nil
	}
	if err := check(m.Capability); err != nil {
		return err
	}
	if err := check(m.ContractID); err != nil {
		return err
	}
	if m.Display != nil {
		if err := check(m.Display.Name); err != nil {
			return err
		}
		if err := check(m.Display.Description); err != nil {
			return err
		}
	}
	for _, i := range m.Inputs {
		if err := check(i.Name); err != nil {
			return err
		}
		for _, x := range i.AcceptedTypes {
			if err := check(x); err != nil {
				return err
			}
		}
		if err := check(i.Cardinality); err != nil {
			return err
		}
	}
	for _, o := range m.Outputs {
		if err := check(o.Name); err != nil {
			return err
		}
		if err := check(o.Type); err != nil {
			return err
		}
		if err := check(o.Cardinality); err != nil {
			return err
		}
	}
	for _, p := range m.Parameters {
		if err := check(p.Name); err != nil {
			return err
		}
		if err := check(p.Kind); err != nil {
			return err
		}
		if p.Default != nil {
			if err := check(*p.Default); err != nil {
				return err
			}
		}
		for _, x := range p.Enum {
			if err := check(x); err != nil {
				return err
			}
		}
	}
	return nil
}
