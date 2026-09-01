package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/cloudlist/pkg/inventory"
	"github.com/projectdiscovery/cloudlist/pkg/schema"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
	"gopkg.in/yaml.v2"
)

// Asset is the safe, scoped portion of a Cloudlist resource exposed by this
// plugin. Credentials, account IDs, private addresses, and provider metadata
// are deliberately excluded.
type Asset struct {
	Host     string `json:"host"`
	Provider string `json:"provider"`
	Service  string `json:"service,omitempty"`
}

type cloudEnumerator interface {
	Enumerate(context.Context, string, cloudOptions) ([]Asset, int, error)
}

type cloudOptions struct {
	ProviderConfig string
	Providers      []string
	ProviderIDs    []string
	Services       []string
}

type cloudlistEnumerator struct{}

func newCloudlistEnumerator() cloudEnumerator { return cloudlistEnumerator{} }

// Enumerate reads the mounted Cloudlist provider configuration, then only
// returns public DNS names that equal the workflow domain or are its
// subdomains. This prevents a project-scoped workflow from fanning out into
// unrelated cloud-account assets.
func (cloudlistEnumerator) Enumerate(ctx context.Context, domain string, opts cloudOptions) ([]Asset, int, error) {
	blocks, err := loadProviderConfig(opts.ProviderConfig)
	if err != nil {
		return nil, 0, err
	}
	blocks = filterProviderBlocks(blocks, opts)
	if len(blocks) == 0 {
		return nil, 0, errorsNew("no configured providers matched the requested filters")
	}
	inv, err := inventory.New(blocks)
	if err != nil {
		return nil, 0, fmt.Errorf("build cloud inventory: %w", err)
	}

	assets := make([]Asset, 0)
	seen := make(map[string]struct{})
	failed := 0
	succeeded := 0
	for _, provider := range inv.Providers {
		if err := ctx.Err(); err != nil {
			return nil, failed, err
		}
		resources, err := provider.Resources(ctx)
		if err != nil {
			failed++
			continue
		}
		succeeded++
		for _, resource := range resources.Items {
			if resource == nil || !resource.Public {
				continue
			}
			hostValue, err := contract.Host(strings.TrimSuffix(strings.TrimSpace(resource.DNSName), "."))
			if err != nil || !withinDomain(hostValue.String(), domain) {
				continue
			}
			host := hostValue.String()
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			assets = append(assets, Asset{Host: host, Provider: provider.Name(), Service: resource.Service})
		}
	}
	if succeeded == 0 && failed > 0 {
		// Do not include provider SDK errors: they can contain account or endpoint
		// information and are not useful to a workflow author.
		return nil, failed, errorsNew("all configured cloud providers failed to enumerate assets")
	}
	return assets, failed, nil
}

func loadProviderConfig(path string) (schema.Options, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provider configuration: %w", err)
	}
	var blocks schema.Options
	if err := yaml.Unmarshal(raw, &blocks); err != nil {
		return nil, fmt.Errorf("parse provider configuration: %w", err)
	}
	if len(blocks) == 0 {
		return nil, errorsNew("provider configuration is empty")
	}
	return blocks, nil
}

func filterProviderBlocks(in schema.Options, opts cloudOptions) schema.Options {
	out := make(schema.Options, 0, len(in))
	for _, block := range in {
		provider := strings.TrimSpace(block["provider"])
		id := strings.TrimSpace(block["id"])
		if provider == "" || (len(opts.Providers) > 0 && !contains(opts.Providers, provider)) || (len(opts.ProviderIDs) > 0 && !contains(opts.ProviderIDs, id)) {
			continue
		}
		copy := make(schema.OptionBlock, len(block)+1)
		for key, value := range block {
			copy[key] = value
		}
		if len(opts.Services) > 0 {
			copy["services"] = strings.Join(opts.Services, ",")
		}
		out = append(out, copy)
	}
	return out
}

func withinDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// errorsNew avoids exposing provider-specific failures through returned scan
// errors while keeping sentinel-free call sites readable.
func errorsNew(message string) error { return fmt.Errorf("cloudlist: %s", message) }
