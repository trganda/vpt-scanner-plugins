package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// capability is the capability string this plugin advertises. It must match the
// host's scan.CapabilitySubdomain constant and the plugin binary's filename.
const capability = "subdomain"

// scanner implements sdk.Scanner for the subdomain capability using subfinder.
type scanner struct {
	enum    enumerator
	initErr error // deferred construction error, surfaced from Execute
	timeout time.Duration
}

// newScanner parses this plugin's config from the environment and builds the
// subfinder runner. A construction failure (e.g. a malformed provider config)
// is captured and returned from Execute rather than crashing the subprocess, so
// the host gets a clear gRPC error instead of a dead plugin.
func newScanner() *scanner {
	cfg, err := loadConfig()
	if err != nil {
		return &scanner{initErr: err}
	}
	enum, err := newSubfinderEnumerator(cfg)
	return &scanner{enum: enum, initErr: err, timeout: cfg.MaxRunTime}
}

// newWithEnumerator is the test seam.
func newWithEnumerator(enum enumerator, timeout time.Duration) *scanner {
	return &scanner{enum: enum, timeout: timeout}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }

// Prepare is a no-op for subdomain — only nuclei needs a pre-scan hook.
func (s *scanner) Prepare(context.Context, string) error { return nil }

func (s *scanner) Execute(ctx context.Context, t sdk.Target) (sdk.Result, error) {
	if s.initErr != nil {
		return sdk.Result{}, s.initErr
	}

	start := time.Now()
	domain := strings.TrimSpace(t.Host)
	if domain == "" {
		return sdk.Result{}, errors.New("subdomain: empty target host")
	}

	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	findings, err := s.enum.Enumerate(ctx, domain)
	if err != nil {
		return sdk.Result{}, err
	}

	hosts := make([]string, 0, len(findings))
	bySource := make(map[string][]string)
	for _, f := range findings {
		hosts = append(hosts, f.Host)
		bySource[f.Source] = append(bySource[f.Source], f.Host)
	}

	raw, err := json.Marshal(map[string]any{
		"domain":     domain,
		"subdomains": hosts,
		"by_source":  bySource,
		"count":      len(hosts),
	})
	if err != nil {
		return sdk.Result{}, err
	}

	return sdk.Result{
		Capability:         capability,
		RawJSON:            raw,
		StartedAtUnixNano:  start.UnixNano(),
		FinishedAtUnixNano: time.Now().UnixNano(),
	}, nil
}

var _ sdk.Scanner = (*scanner)(nil)
