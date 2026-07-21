package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
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
	return s.ExecuteStream(ctx, t, nil)
}

func (s *scanner) ExecuteStream(ctx context.Context, t sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	start := time.Now()
	seq := int64(0)
	emit := func(level, typ, message string, fields map[string]string) error {
		seq++
		if sink == nil {
			return nil
		}
		e := sdk.NewEvent(level, typ, message, fields)
		e.Sequence = seq
		return sink(e)
	}
	_ = emit("info", "scan_started", "port scan started", nil)
	host := strings.TrimSpace(t.Host)
	if host == "" {
		_ = emit("error", "scan_failed", "port scan failed", map[string]string{"reason": "invalid_target"})
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
		_ = emit("error", "scan_failed", "port scan failed", map[string]string{"reason": "scanner_error"})
		return sdk.Result{}, err
	}

	raw, err := json.Marshal(map[string]any{
		"host":  host,
		"ports": found,
		"count": len(found),
	})
	if err != nil {
		_ = emit("error", "scan_failed", "port scan failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	_ = emit("info", "scan_completed", "port scan completed", map[string]string{"count": strconv.Itoa(len(found))})

	return sdk.Result{
		Capability:         capability,
		RawJSON:            raw,
		StartedAtUnixNano:  start.UnixNano(),
		FinishedAtUnixNano: time.Now().UnixNano(),
	}, nil
}

var _ sdk.Scanner = (*scanner)(nil)
