// Command verify-plugin-release launches one release artifact and checks its
// Describe identity against the signed release descriptor inputs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("verify-plugin-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	pluginPath := flags.String("plugin", "", "plugin executable to inspect")
	descriptorPath := flags.String("descriptor", "", "canonical release descriptor")
	capability := flags.String("capability", "", "expected capability")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *pluginPath == "" || *descriptorPath == "" || *capability == "" {
		return errors.New("plugin, descriptor, and capability are required")
	}

	rawDescriptor, err := os.ReadFile(*descriptorPath)
	if err != nil {
		return err
	}
	descriptor, err := release.Parse(rawDescriptor)
	if err != nil {
		return err
	}
	absolutePlugin, err := filepath.Abs(*pluginPath)
	if err != nil {
		return err
	}
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  sdk.Handshake,
		Plugins:          sdk.PluginMap(nil),
		Cmd:              exec.Command(absolutePlugin),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Logger:           hclog.NewNullLogger(),
		StartTimeout:     15 * time.Second,
	})
	defer client.Kill()
	rpc, err := client.Client()
	if err != nil {
		return err
	}
	rawPlugin, err := rpc.Dispense(sdk.PluginName)
	if err != nil {
		return err
	}
	describer, ok := rawPlugin.(sdk.Describer)
	if !ok {
		return fmt.Errorf("plugin dispensed %T, want sdk.Describer", rawPlugin)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	description, err := describer.Describe(ctx)
	if err != nil {
		return err
	}
	return verify(description, descriptor, *capability)
}

func verify(description sdk.Description, descriptor release.Descriptor, capability string) error {
	var expected *release.Plugin
	for i := range descriptor.Plugins {
		if descriptor.Plugins[i].Capability == capability {
			expected = &descriptor.Plugins[i]
			break
		}
	}
	if expected == nil {
		return fmt.Errorf("capability %q is absent from release descriptor", capability)
	}
	if description.Capability != capability ||
		description.PluginVersion != expected.PluginVersion ||
		description.SDKVersion != descriptor.SDKVersion ||
		description.SourceCommit != descriptor.Source.Commit ||
		description.ProtocolVersion != descriptor.ProtocolVersion ||
		!slices.Equal(description.Features, expected.Features) ||
		!maps.Equal(description.RuntimeRequirements, expected.RuntimeRequirements) {
		return fmt.Errorf("plugin %q Describe identity does not match release descriptor", capability)
	}
	return nil
}
