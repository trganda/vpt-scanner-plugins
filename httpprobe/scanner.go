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
// host's scan.CapabilityHTTPProbe constant and the plugin binary's filename.
const capability = "httpprobe"

// scanner implements sdk.Scanner for the httpprobe capability using httpx.
type scanner struct {
	prober  prober
	timeout time.Duration
}

func newScanner() (*scanner, error) {
	opts, err := loadOptions()
	if err != nil {
		return nil, err
	}
	p, err := newHTTPXProber(opts)
	if err != nil {
		return nil, err
	}
	return &scanner{prober: p, timeout: opts.MaxRunTime}, nil
}

// newWithProber is the test seam.
func newWithProber(p prober, timeout time.Duration) *scanner {
	return &scanner{prober: p, timeout: timeout}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }

// Prepare is a no-op for httpprobe — only nuclei needs a pre-scan hook.
func (s *scanner) Prepare(context.Context, string) error { return nil }

func (s *scanner) Execute(ctx context.Context, t sdk.Target) (sdk.Result, error) {
	return s.ExecuteStream(ctx, t, nil)
}

func (s *scanner) ExecuteStream(ctx context.Context, t sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return sdk.Result{}, errors.New("httpprobe: empty target host")
	}
	t.Host = host
	results, err := s.executeBatch(ctx, []sdk.Target{t}, sink)
	if err != nil {
		return sdk.Result{}, err
	}
	return results[0], nil
}

// ExecuteBatch is the optional additive batch surface. Results are deliberately
// returned in input order, including empty probe sets.
func (s *scanner) ExecuteBatch(ctx context.Context, targets []sdk.Target, sink sdk.EventSink) ([]sdk.Result, error) {
	return s.executeBatch(ctx, targets, sink)
}

func (s *scanner) executeBatch(ctx context.Context, targets []sdk.Target, sink sdk.EventSink) ([]sdk.Result, error) {
	if len(targets) == 0 {
		return nil, errors.New("httpprobe: empty batch")
	}
	for i := range targets {
		targets[i].Host = strings.TrimSpace(targets[i].Host)
		if targets[i].Host == "" {
			return nil, errors.New("httpprobe: empty target host")
		}
	}
	// Production starts this timeout after acquiring the global httpx gate.
	// Test doubles still get the same bounded call contract.
	if _, real := s.prober.(*httpxProber); !real && s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	sequence := int64(0)
	emit := func(index int, level, typ, message string, fields map[string]string) error {
		if sink == nil {
			return nil
		}
		sequence++
		e := sdk.NewEvent(level, typ, message, fields)
		e.Sequence, e.Index = sequence, index
		return sink(e)
	}
	for i := range targets {
		if err := emit(i, "info", "scan_started", "http probe started", nil); err != nil {
			return nil, err
		}
	}
	results, err := s.prober.ProbeBatch(ctx, targets)
	if err != nil {
		for i := range targets {
			_ = emit(i, "error", "scan_failed", "http probe failed", map[string]string{"reason": "scanner_error"})
		}
		return nil, err
	}
	for i, result := range results {
		var raw struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(result.RawJSON, &raw); err != nil {
			return nil, err
		}
		if err := emit(i, "info", "scan_completed", "http probe completed", map[string]string{"count": strconv.Itoa(raw.Count)}); err != nil {
			return nil, err
		}
	}
	return results, nil
}

func executionOptions(base Options, p map[string]string, primary bool) Options {
	// The primary contract owns its defaults; legacy compatibility intentionally
	// continues to inherit the historical environment configuration.
	if primary {
		base.Timeout = 10 * time.Second
		base.FollowRedirects = true
		base.TechDetect = true
		base.Methods = nil
		base.ASN = false
	}
	if v := p["request_timeout_seconds"]; v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			base.Timeout = time.Duration(n) * time.Second
		}
	}
	if v := p["follow_redirects"]; v != "" {
		base.FollowRedirects = v == "true"
	}
	if v := p["tech_detect"]; v != "" {
		base.TechDetect = v == "true"
	}
	if v := p["asn"]; v != "" {
		base.ASN = v == "true"
	}
	if v := p["methods"]; v != "" {
		base.Methods = strings.Split(v, ",")
	}
	return base
}

var _ sdk.Scanner = (*scanner)(nil)
var _ sdk.BatchScanner = (*scanner)(nil)
