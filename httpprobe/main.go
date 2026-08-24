// Command httpprobe is the projectdiscovery/httpx HTTP probing tool as a
// standalone go-plugin gRPC plugin, launched as a subprocess by the scanner
// host. All httpx/tlsx dependency weight lives in this module's go.mod, keeping
// it out of the scanner host binary.
package main

import (
	"fmt"
	"os"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

func pluginOptions() sdk.ManifestOptions { return sdk.ManifestOptions{} }

func main() {
	m := manifest()
	if handled, err := sdk.PrintManifestIfRequested(m, os.Args[1:], os.Stdout); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := sdk.ServeWithManifest(newScanner(), m, pluginOptions()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
