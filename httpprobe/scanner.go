package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/trganda/vpt-backend/plugins/sdk"
)

// capability is the capability string this plugin advertises. It must match the
// host's scan.CapabilityHTTPProbe constant and the plugin binary's filename.
const capability = "httpprobe"

// scanner implements sdk.Scanner for the httpprobe capability using httpx.
type scanner struct {
	prober  prober
	initErr error // deferred construction error, surfaced from Execute
	timeout time.Duration
}

func newScanner() *scanner {
	opts, err := loadOptions()
	if err != nil {
		return &scanner{initErr: err}
	}
	p, err := newHTTPXProber(opts)
	return &scanner{prober: p, initErr: err, timeout: opts.MaxRunTime}
}

// newWithProber is the test seam.
func newWithProber(p prober, timeout time.Duration) *scanner {
	return &scanner{prober: p, timeout: timeout}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }

// Prepare is a no-op for httpprobe — only nuclei needs a pre-scan hook.
func (s *scanner) Prepare(context.Context, string) error { return nil }

func (s *scanner) Execute(ctx context.Context, t sdk.Target) (sdk.Result, error) {
	if s.initErr != nil {
		return sdk.Result{}, s.initErr
	}

	start := time.Now()
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return sdk.Result{}, errors.New("httpprobe: empty target host")
	}

	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	// Default to the two canonical web ports; callers may override via
	// Params["ports"] (e.g. "80,443,8080").
	ports := "80,443"
	if p, ok := t.Params["ports"]; ok && p != "" {
		ports = p
	}

	probes, err := s.prober.Probe(ctx, host, ports)
	if err != nil {
		return sdk.Result{}, err
	}

	raw, err := json.Marshal(map[string]any{
		"host":   host,
		"probes": probes,
		"count":  len(probes),
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
