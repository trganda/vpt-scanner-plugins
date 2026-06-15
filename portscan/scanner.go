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
// host's scan.CapabilityPortScan constant and the plugin binary's filename.
const capability = "portscan"

// scanner implements sdk.Scanner for the portscan capability using naabu as the
// underlying TCP connect scanner. It is the plugin-side equivalent of the old
// in-process portscan.Executor.
type scanner struct {
	ps      portScanner
	timeout time.Duration
}

func newScanner() *scanner {
	return &scanner{ps: newNaabuScanner(), timeout: 5 * time.Minute}
}

// newWithScanner is the test seam: tests inject a fake portScanner so they
// don't pull the naabu SDK or live network into the unit suite.
func newWithScanner(ps portScanner, timeout time.Duration) *scanner {
	return &scanner{ps: ps, timeout: timeout}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }

// Prepare is a no-op for portscan — only nuclei needs a pre-scan hook.
func (s *scanner) Prepare(context.Context, string) error { return nil }

func (s *scanner) Execute(ctx context.Context, t sdk.Target) (sdk.Result, error) {
	start := time.Now()
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return sdk.Result{}, errors.New("portscan: empty target host")
	}

	// Per-call timeout cap, layered under the workflow's StartToCloseTimeout.
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	// Default to top-100 common ports; callers may override via Params["ports"].
	ports := "100"
	if p, ok := t.Params["ports"]; ok && p != "" {
		ports = p
	}

	found, err := s.ps.Scan(ctx, host, ports)
	if err != nil {
		return sdk.Result{}, err
	}

	raw, err := json.Marshal(map[string]any{
		"host":  host,
		"ports": found,
		"count": len(found),
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
