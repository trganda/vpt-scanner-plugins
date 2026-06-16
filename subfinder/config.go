package main

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// config is subfinder's slice of the VPT_NODE_* namespace, parsed directly from
// the environment the scanner host passed through to this subprocess. It mirrors
// the Subfinder* fields that used to live in internal/platform/config.Scanner.
type config struct {
	ProviderConfig string        `envconfig:"VPT_NODE_SUBFINDER_PROVIDER_CONFIG" default:""`
	Timeout        time.Duration `envconfig:"VPT_NODE_SUBFINDER_TIMEOUT" default:"30s"`
	MaxRunTime     time.Duration `envconfig:"VPT_NODE_SUBFINDER_MAX_RUN_TIME" default:"10m"`
	Threads        int           `envconfig:"VPT_NODE_SUBFINDER_THREADS" default:"10"`
	AllSources     bool          `envconfig:"VPT_NODE_SUBFINDER_ALL_SOURCES" default:"false"`
	Sources        []string      `envconfig:"VPT_NODE_SUBFINDER_SOURCES"`
	ExcludeSources []string      `envconfig:"VPT_NODE_SUBFINDER_EXCLUDE_SOURCES"`
	Resolvers      []string      `envconfig:"VPT_NODE_SUBFINDER_RESOLVERS"`
}

func loadConfig() (config, error) {
	var c config
	err := envconfig.Process("", &c)
	return c, err
}
