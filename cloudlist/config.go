package main

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// config keeps cloud credentials out of workflow definitions. The mounted
// Cloudlist provider configuration may refer to credential environment
// variables, but its path is configured only at the scanner-node level.
type config struct {
	ProviderConfig string        `envconfig:"VPT_NODE_CLOUDLIST_PROVIDER_CONFIG" required:"true"`
	MaxRunTime     time.Duration `envconfig:"VPT_NODE_CLOUDLIST_MAX_RUN_TIME" default:"10m"`
}

func loadConfig() (config, error) {
	var c config
	err := envconfig.Process("", &c)
	return c, err
}
