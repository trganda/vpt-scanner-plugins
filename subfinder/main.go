// Command subfinder is the projectdiscovery/subfinder passive subdomain
// enumeration tool as a standalone go-plugin gRPC plugin, launched as a
// subprocess by the scanner host. All subfinder dependency weight lives in this
// module's go.mod, keeping it out of the scanner host binary.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func subdomainOutputMapper(_ sdk.Target, result sdk.Result) ([]contract.NamedOutput, error) {
	var raw struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(result.RawJSON, &raw); err != nil {
		return nil, err
	}
	values := make([]contract.Value, 0, len(raw.Subdomains))
	for _, host := range raw.Subdomains {
		v, err := contract.Host(host)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return []contract.NamedOutput{{Name: "subdomains", Values: values}}, nil
}

func pluginOptions() sdk.ManifestOptions {
	return sdk.ManifestOptions{OutputMapper: subdomainOutputMapper}
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
