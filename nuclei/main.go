// Command nuclei is the projectdiscovery/nuclei vulnerability scanner as a
// standalone go-plugin gRPC plugin, launched as a subprocess by the scanner
// host. It implements both Execute (scan) and Prepare (pre-scan template
// sync). All nuclei dependency weight — the heaviest of the tools — lives in
// this module's go.mod, keeping it out of the scanner host binary.
package main

import (
	"fmt"
	"os"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

func nucleiTargetMapper(target sdk.Target) (sdk.Target, error) {
	if target.Params["severity"] == "all" {
		delete(target.Params, "severity")
	}
	return target, nil
}

func pluginOptions() sdk.ManifestOptions {
	return sdk.ManifestOptions{TargetMapper: nucleiTargetMapper}
}

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
