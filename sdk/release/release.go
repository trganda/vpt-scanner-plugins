// Package release defines the canonical scanner plugin release descriptor.
package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

const (
	// SchemaVersion is the only release descriptor schema supported by this SDK.
	SchemaVersion = 1
	// SizeLimit bounds both source and canonical descriptors.
	SizeLimit = 256 * 1024
)

var (
	versionRE      = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	commitRE       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	aggregateTagRE = regexp.MustCompile(`^(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$`)
	scopedTagRE    = regexp.MustCompile(`^plugin-(subdomain|portscan|httpprobe|vuln|katana|cloudlist)-(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$`)
	nameRE         = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	assetRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestRE       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoOwnerRE    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repoNameRE     = regexp.MustCompile(`^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?$`)
)

// Descriptor binds immutable source and SDK identities to one or more plugins.
type Descriptor struct {
	SchemaVersion   int      `json:"schema_version"`
	Source          Source   `json:"source"`
	SDKVersion      string   `json:"sdk_version"`
	ProtocolVersion uint32   `json:"protocol_version"`
	Plugins         []Plugin `json:"plugins"`
}

// Source identifies the repository state from which every artifact was built.
type Source struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Commit     string `json:"commit"`
}

// Plugin describes one capability in a release.
type Plugin struct {
	Capability          string            `json:"capability"`
	PluginVersion       string            `json:"plugin_version"`
	Artifacts           []Artifact        `json:"artifacts"`
	Features            []string          `json:"features"`
	RuntimeRequirements map[string]string `json:"runtime_requirements"`
}

// Artifact identifies one platform artifact and its canonical digest.
type Artifact struct {
	Name         string `json:"name"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
}

// Parse strictly decodes and validates a release descriptor.
func Parse(raw []byte) (Descriptor, error) {
	if len(raw) > SizeLimit || !utf8.Valid(raw) {
		return Descriptor{}, errors.New("release descriptor is invalid or too large")
	}
	if err := validateJSONStringEscapes(raw); err != nil {
		return Descriptor{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := parseValue(dec, &value, 0); err != nil {
		return Descriptor{}, err
	}
	if value == nil {
		return Descriptor{}, errors.New("release descriptor root is null")
	}
	if err := ensureEOF(dec); err != nil {
		return Descriptor{}, err
	}
	canonical, err := encodeCanonical(value)
	if err != nil {
		return Descriptor{}, err
	}
	if len(canonical) > SizeLimit {
		return Descriptor{}, errors.New("canonical release descriptor too large")
	}
	var descriptor Descriptor
	strict := json.NewDecoder(bytes.NewReader(canonical))
	strict.DisallowUnknownFields()
	if err = strict.Decode(&descriptor); err != nil {
		return Descriptor{}, err
	}
	if err = ensureEOF(strict); err != nil {
		return Descriptor{}, err
	}
	if err = Validate(descriptor); err != nil {
		return Descriptor{}, err
	}
	return clone(descriptor), nil
}

// Validate checks all release descriptor identities, limits, and ordering.
func Validate(descriptor Descriptor) error {
	if descriptor.SchemaVersion != SchemaVersion {
		return errors.New("unsupported release descriptor schema version")
	}
	capability, releaseVersion, scoped := parseTag(descriptor.Source.Tag)
	if !validRepository(descriptor.Source.Repository) || !versionRE.MatchString(releaseVersion) || !commitRE.MatchString(descriptor.Source.Commit) {
		return errors.New("invalid release source")
	}
	if !versionRE.MatchString(descriptor.SDKVersion) || descriptor.ProtocolVersion != contract.ProtocolVersion {
		return errors.New("invalid SDK identity")
	}
	knownCapabilities := contract.Capabilities()
	if scoped && len(descriptor.Plugins) != 1 {
		return errors.New("capability-scoped release must contain exactly one plugin")
	}
	if !scoped && len(descriptor.Plugins) != len(knownCapabilities) {
		return errors.New("aggregate release must contain every plugin")
	}
	if len(descriptor.Plugins) == 0 {
		return errors.New("invalid plugin count")
	}
	for i, plugin := range descriptor.Plugins {
		expectedCapability := string(knownCapabilities[i])
		if scoped {
			expectedCapability = capability
		}
		if plugin.Capability != expectedCapability || plugin.PluginVersion != releaseVersion {
			return errors.New("invalid plugin identity")
		}
		if len(plugin.Artifacts) != 2 || plugin.Features == nil || plugin.RuntimeRequirements == nil {
			return errors.New("plugin artifacts, features, and runtime requirements are required")
		}
		for artifactIndex, architecture := range []string{"amd64", "arm64"} {
			artifact := plugin.Artifacts[artifactIndex]
			expectedName := plugin.Capability + "_linux_" + architecture
			if artifact.Name != expectedName || artifact.OS != "linux" || artifact.Architecture != architecture || !assetRE.MatchString(artifact.Name) || !digestRE.MatchString(artifact.SHA256) {
				return errors.New("invalid or duplicate artifact")
			}
		}
		if err := validateStringSet(plugin.Features, "feature"); err != nil {
			return err
		}
		for key, value := range plugin.RuntimeRequirements {
			if !nameRE.MatchString(key) || value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 }) >= 0 {
				return errors.New("invalid runtime requirement")
			}
		}
	}
	raw, err := json.Marshal(descriptor)
	if err != nil || len(raw) > SizeLimit {
		return errors.New("release descriptor too large")
	}
	return nil
}

// Canonical validates descriptor and returns compact canonical JSON. Object
// keys are UTF-8 byte ordered; array order remains semantic.
func Canonical(descriptor Descriptor) ([]byte, error) {
	if err := Validate(descriptor); err != nil {
		return nil, err
	}
	if err := validateStrings(descriptor); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err = dec.Decode(&value); err != nil {
		return nil, err
	}
	out, err := encodeCanonical(value)
	if err != nil {
		return nil, err
	}
	if len(out) > SizeLimit {
		return nil, errors.New("canonical release descriptor too large")
	}
	return out, nil
}

func parseTag(tag string) (capability, version string, scoped bool) {
	if matches := scopedTagRE.FindStringSubmatch(tag); matches != nil {
		return matches[1], matches[2], true
	}
	if matches := aggregateTagRE.FindStringSubmatch(tag); matches != nil {
		return "", matches[1], false
	}
	return "", "", false
}

func validRepository(repository string) bool {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 {
		return false
	}
	return repoOwnerRE.MatchString(parts[0]) && !strings.Contains(parts[0], "--") && repoNameRE.MatchString(parts[1]) && parts[1] != "." && parts[1] != ".."
}

func validateStringSet(values []string, label string) error {
	seen := map[string]bool{}
	for i, value := range values {
		if !nameRE.MatchString(value) || seen[value] {
			return fmt.Errorf("invalid or duplicate %s", label)
		}
		if i > 0 && values[i-1] >= value {
			return fmt.Errorf("%ss are not in canonical order", label)
		}
		seen[value] = true
	}
	return nil
}

func validateStrings(descriptor Descriptor) error {
	values := []string{descriptor.Source.Repository, descriptor.Source.Tag, descriptor.Source.Commit, descriptor.SDKVersion}
	for _, plugin := range descriptor.Plugins {
		values = append(values, plugin.Capability, plugin.PluginVersion)
		values = append(values, plugin.Features...)
		for _, artifact := range plugin.Artifacts {
			values = append(values, artifact.Name, artifact.OS, artifact.Architecture, artifact.SHA256)
		}
		for key, value := range plugin.RuntimeRequirements {
			values = append(values, key, value)
		}
	}
	for _, value := range values {
		if !utf8.ValidString(value) {
			return errors.New("release descriptor contains invalid UTF-8")
		}
	}
	return nil
}

func clone(descriptor Descriptor) Descriptor {
	out := descriptor
	out.Plugins = append([]Plugin(nil), descriptor.Plugins...)
	for i := range out.Plugins {
		out.Plugins[i].Artifacts = append([]Artifact(nil), descriptor.Plugins[i].Artifacts...)
		out.Plugins[i].Features = append([]string(nil), descriptor.Plugins[i].Features...)
		out.Plugins[i].RuntimeRequirements = make(map[string]string, len(descriptor.Plugins[i].RuntimeRequirements))
		for key, value := range descriptor.Plugins[i].RuntimeRequirements {
			out.Plugins[i].RuntimeRequirements[key] = value
		}
	}
	return out
}

func parseValue(decoder *json.Decoder, out *any, depth int) error {
	if depth > 64 {
		return errors.New("release descriptor nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key := keyToken.(string)
				if _, exists := object[key]; exists {
					return fmt.Errorf("duplicate key %q", key)
				}
				var item any
				if err = parseValue(decoder, &item, depth+1); err != nil {
					return err
				}
				object[key] = item
			}
			if _, err = decoder.Token(); err != nil {
				return err
			}
			*out = object
			return nil
		case '[':
			array := []any{}
			for decoder.More() {
				var item any
				if err = parseValue(decoder, &item, depth+1); err != nil {
					return err
				}
				array = append(array, item)
			}
			if _, err = decoder.Token(); err != nil {
				return err
			}
			*out = array
			return nil
		default:
			return errors.New("invalid JSON delimiter")
		}
	default:
		if value == nil {
			return errors.New("null is not allowed")
		}
		*out = value
		return nil
	}
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func encodeCanonical(value any) ([]byte, error) {
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare([]byte(keys[i]), []byte(keys[j])) < 0 })
		var out bytes.Buffer
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			encodedKey, _ := encodeString(key)
			out.Write(encodedKey)
			out.WriteByte(':')
			encodedValue, err := encodeCanonical(value[key])
			if err != nil {
				return nil, err
			}
			out.Write(encodedValue)
		}
		out.WriteByte('}')
		return out.Bytes(), nil
	case []any:
		var out bytes.Buffer
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			encoded, err := encodeCanonical(item)
			if err != nil {
				return nil, err
			}
			out.Write(encoded)
		}
		out.WriteByte(']')
		return out.Bytes(), nil
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return nil, errors.New("invalid number")
		}
		if _, err := strconv.ParseInt(string(value), 10, 64); err != nil {
			return nil, err
		}
		return []byte(value), nil
	default:
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(value); err != nil {
			return nil, err
		}
		return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
	}
}

func encodeString(value string) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func validateJSONStringEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw); i++ {
			if raw[i] == '"' {
				break
			}
			if raw[i] != '\\' {
				continue
			}
			if i+1 >= len(raw) {
				return errors.New("invalid escape")
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			if i+5 >= len(raw) {
				return errors.New("invalid unicode escape")
			}
			value, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
			if err != nil {
				return err
			}
			if value >= 0xdc00 && value <= 0xdfff {
				return errors.New("unpaired surrogate")
			}
			if value >= 0xd800 && value <= 0xdbff {
				if i+11 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
					return errors.New("unpaired surrogate")
				}
				low, lowErr := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
				if lowErr != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired surrogate")
				}
				i += 6
			}
			i += 5
		}
	}
	return nil
}
