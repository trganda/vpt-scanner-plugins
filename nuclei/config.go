package main

import (
	"os"
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
)

// config is nuclei's slice of the VPT_NODE_* namespace, parsed from the
// environment the scanner host passed through to this subprocess. It mirrors
// the Nuclei* fields that used to live in internal/platform/config.Scanner plus
// the vuln executor Options.
type config struct {
	// BundleURL is the control plane GET /v1/templates/bundle endpoint used by
	// Prepare to sync the template cache.
	BundleURL string `envconfig:"VPT_NODE_NUCLEI_BUNDLE_URL" required:"true"`
	// TemplateDir is the persistent cache directory for YAML files. Empty →
	// $HOME/.vpt/nuclei-templates (see resolveTemplateDir).
	TemplateDir         string `envconfig:"VPT_NODE_NUCLEI_TEMPLATE_DIR" default:""`
	TemplateConcurrency int    `envconfig:"VPT_NODE_NUCLEI_TEMPLATE_CONCURRENCY" default:"25"`
	HostConcurrency     int    `envconfig:"VPT_NODE_NUCLEI_HOST_CONCURRENCY" default:"25"`
	NetworkTimeout      int    `envconfig:"VPT_NODE_NUCLEI_NETWORK_TIMEOUT" default:"10"`
	NetworkRetries      int    `envconfig:"VPT_NODE_NUCLEI_NETWORK_RETRIES" default:"2"`
}

func loadConfig() (config, error) {
	var c config
	if err := envconfig.Process("", &c); err != nil {
		return c, err
	}
	c.TemplateDir = resolveTemplateDir(c.TemplateDir)
	return c, nil
}

// resolveTemplateDir returns the persistent template cache directory, mirroring
// the host's cmd/scanner default so Prepare (sync) and Execute (scan) agree on
// the location.
func resolveTemplateDir(configured string) string {
	if configured != "" {
		return configured
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".vpt", "nuclei-templates")
	}
	return ".vpt/nuclei-templates"
}
