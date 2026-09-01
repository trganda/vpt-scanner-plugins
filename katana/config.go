package main

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// config contains Katana's process-level defaults. Per-step parameters may
// narrow or override these non-secret operational settings.
type config struct {
	Timeout     time.Duration `envconfig:"VPT_NODE_KATANA_TIMEOUT" default:"10s"`
	MaxRunTime  time.Duration `envconfig:"VPT_NODE_KATANA_MAX_RUN_TIME" default:"5m"`
	Concurrency int           `envconfig:"VPT_NODE_KATANA_CONCURRENCY" default:"10"`
	RateLimit   int           `envconfig:"VPT_NODE_KATANA_RATE_LIMIT" default:"150"`
	MaxDepth    int           `envconfig:"VPT_NODE_KATANA_MAX_DEPTH" default:"3"`
	ScrapeJS    bool          `envconfig:"VPT_NODE_KATANA_SCRAPE_JS" default:"false"`
}

func loadConfig() (config, error) {
	var c config
	err := envconfig.Process("", &c)
	return c, err
}
