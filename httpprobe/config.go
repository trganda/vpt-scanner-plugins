package main

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Options is httpprobe's slice of the VPT_NODE_* namespace, parsed from the
// environment the scanner host passed through to this subprocess. It mirrors
// the HTTPProbe* (and shared PDCP) fields that used to live in
// internal/platform/config.Scanner, and is also what the prober reads.
type Options struct {
	Timeout         time.Duration `envconfig:"VPT_NODE_HTTPPROBE_TIMEOUT" default:"10s"`
	MaxRunTime      time.Duration `envconfig:"VPT_NODE_HTTPPROBE_MAX_RUN_TIME" default:"5m"`
	Threads         int           `envconfig:"VPT_NODE_HTTPPROBE_THREADS" default:"25"`
	FollowRedirects bool          `envconfig:"VPT_NODE_HTTPPROBE_FOLLOW_REDIRECTS" default:"true"`
	TechDetect      bool          `envconfig:"VPT_NODE_HTTPPROBE_TECH_DETECT" default:"true"`
	Methods         []string      `envconfig:"VPT_NODE_HTTPPROBE_METHODS"`
	ASN             bool          `envconfig:"VPT_NODE_HTTPPROBE_ASN" default:"false"`
	PdcpAPIKey      string        `envconfig:"VPT_NODE_PDCP_API_KEY" default:""`
}

func loadOptions() (Options, error) {
	var o Options
	err := envconfig.Process("", &o)
	return o, err
}
