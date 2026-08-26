package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/trganda/vpt-scanner-plugins/sdk/runtimeconfig"
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
	d, err := runtimeconfig.Compile(runtimeManifest())
	if err != nil {
		return Options{}, err
	}
	var o Options
	if err := envconfig.Process("", &o); err != nil {
		return o, err
	}
	raw := os.Getenv("VPT_PLUGIN_RUNTIME_CONFIG")
	if raw != "" {
		pluginValues, _, err := d.ParseValues([]byte(raw))
		if err != nil {
			return o, err
		}
		if v, ok := pluginValues["threads"]; ok {
			n, e := strconv.Atoi(v)
			if e != nil {
				return o, e
			}
			o.Threads = n
		}
		if v, ok := pluginValues["max_run_time_seconds"]; ok {
			n, e := strconv.Atoi(v)
			if e != nil {
				return o, e
			}
			o.MaxRunTime = time.Duration(n) * time.Second
		}
	}
	if err := validateOptions(o); err != nil {
		return Options{}, err
	}
	return o, nil
}

func validateOptions(o Options) error {
	if o.Threads < 1 || o.MaxRunTime < time.Second || o.Timeout < time.Second {
		return fmt.Errorf("httpprobe: threads and timeouts must be positive")
	}
	allowed := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true}
	for _, method := range o.Methods {
		method = strings.TrimSpace(method)
		if !allowed[method] {
			return fmt.Errorf("httpprobe: unsupported method %q", method)
		}
	}
	return nil
}
