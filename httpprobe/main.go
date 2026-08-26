// Command httpprobe is the projectdiscovery/httpx HTTP probing tool as a
// standalone go-plugin gRPC plugin, launched as a subprocess by the scanner
// host. All httpx/tlsx dependency weight lives in this module's go.mod, keeping
// it out of the scanner host binary.
package main

import (
	"fmt"
	"os"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func pluginOptions() sdk.ManifestOptions { return sdk.ManifestOptions{} }

func main() {
	m := manifest()
	runtime := runtimeManifest()
	if handled, err := sdk.PrintManifestsIfRequested(m, []contract.Manifest{legacyManifest()}, &runtime, os.Args[1:], os.Stdout); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	s, err := newScanner()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := sdk.ServeWithManifests(s, m, []contract.Manifest{legacyManifest()}, pluginOptions()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
