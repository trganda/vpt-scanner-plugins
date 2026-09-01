// Command katana exposes ProjectDiscovery Katana as a VPT go-plugin.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func katanaOutputMapper(_ sdk.Target, result sdk.Result) ([]contract.NamedOutput, error) {
	var raw struct {
		URLs []string `json:"urls"`
	}
	if err := json.Unmarshal(result.RawJSON, &raw); err != nil {
		return nil, err
	}
	values := make([]contract.Value, 0, len(raw.URLs))
	for _, found := range raw.URLs {
		value, err := contract.URL(found)
		if err != nil {
			continue
		}
		values = append(values, value)
	}
	return []contract.NamedOutput{{Name: "urls", Values: values}}, nil
}

func pluginOptions() sdk.ManifestOptions {
	return sdk.ManifestOptions{OutputMapper: katanaOutputMapper}
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
