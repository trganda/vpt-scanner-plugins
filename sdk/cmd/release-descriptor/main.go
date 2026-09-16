// Command release-descriptor emits the canonical descriptor for built plugin
// artifacts. Release automation includes the descriptor in SLSA provenance.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/release"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release-descriptor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dist := flags.String("dist", "", "directory containing release artifacts")
	repository := flags.String("repository", "", "source repository as owner/name")
	tag := flags.String("tag", "", "aggregate or capability-scoped release tag")
	commit := flags.String("commit", "", "lowercase 40-character source commit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dist == "" || *repository == "" || *tag == "" || *commit == "" {
		return errors.New("dist, repository, tag, and commit are required")
	}

	capabilities, version, err := releaseSelection(*tag)
	if err != nil {
		return err
	}
	descriptor := release.Descriptor{
		SchemaVersion:   release.SchemaVersion,
		Source:          release.Source{Repository: *repository, Tag: *tag, Commit: *commit},
		SDKVersion:      sdk.Version,
		ProtocolVersion: sdk.ContractProtocolVersion,
		Plugins:         make([]release.Plugin, 0, len(capabilities)),
	}
	for _, capability := range capabilities {
		plugin := release.Plugin{
			Capability:          capability,
			PluginVersion:       version,
			Features:            []string{"execute_stream", "typed_contracts"},
			RuntimeRequirements: map[string]string{"libc": "glibc", "os": "linux"},
		}
		for _, architecture := range []string{"amd64", "arm64"} {
			name := capability + "_linux_" + architecture
			digest, digestErr := fileDigest(filepath.Join(*dist, name))
			if digestErr != nil {
				return digestErr
			}
			plugin.Artifacts = append(plugin.Artifacts, release.Artifact{Name: name, OS: "linux", Architecture: architecture, SHA256: digest})
		}
		descriptor.Plugins = append(descriptor.Plugins, plugin)
	}

	canonical, err := release.Canonical(descriptor)
	if err != nil {
		return err
	}
	_, err = output.Write(canonical)
	return err
}

func releaseSelection(tag string) ([]string, string, error) {
	capabilities := sdk.Capabilities()
	if strings.HasPrefix(tag, "v") {
		return capabilities, tag, nil
	}
	for _, capability := range capabilities {
		prefix := "plugin-" + capability + "-"
		if strings.HasPrefix(tag, prefix) {
			return []string{capability}, strings.TrimPrefix(tag, prefix), nil
		}
	}
	return nil, "", fmt.Errorf("unsupported release tag %q", tag)
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
