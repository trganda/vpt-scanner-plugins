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
	initErr error // deferred construction error, surfaced from Execute
	opts    Options
	timeout time.Duration
}

func newScanner() *scanner {
	opts, err := loadOptions()
	if err != nil {
		return &scanner{initErr: err}
	}
	p, err := newHTTPXProber(opts)
	return &scanner{prober: p, initErr: err, opts: opts, timeout: opts.MaxRunTime}
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
	_ = emit("info", "scan_started", "http probe started", nil)
	if s.initErr != nil {
		_ = emit("error", "scan_failed", "http probe failed", map[string]string{"reason": "initialization"})
		return sdk.Result{}, s.initErr
	}

	start := time.Now()
	host := strings.TrimSpace(t.Host)
	if host == "" {
		_ = emit("error", "scan_failed", "http probe failed", map[string]string{"reason": "invalid_target"})
		return sdk.Result{}, errors.New("httpprobe: empty target host")
	}

	probeOpts := probeOptionsFromParams(t.Params, s.opts)
	if maxRun := probeMaxRunTime(t.Params, s.timeout); maxRun > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxRun)
		defer cancel()
	}

	// Default to the two canonical web ports; callers may override via
	// Params["ports"] (e.g. "80,443,8080").
	ports := "80,443"
	if p, ok := t.Params["ports"]; ok && p != "" {
		ports = p
	}

	probes, err := s.prober.Probe(ctx, host, ports, probeOpts)
	if err != nil {
		_ = emit("error", "scan_failed", "http probe failed", map[string]string{"reason": "scanner_error"})
		return sdk.Result{}, err
	}

	raw, err := json.Marshal(map[string]any{
		"host":   host,
		"probes": probes,
		"count":  len(probes),
	})
	if err != nil {
		_ = emit("error", "scan_failed", "http probe failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	_ = emit("info", "scan_completed", "http probe completed", map[string]string{"count": strconv.Itoa(len(probes))})

	return sdk.Result{
		Capability:         capability,
		RawJSON:            raw,
		StartedAtUnixNano:  start.UnixNano(),
		FinishedAtUnixNano: time.Now().UnixNano(),
	}, nil
}

var _ sdk.Scanner = (*scanner)(nil)

// probeOptionsFromParams resolves one call's probing tuning by applying step
// params over the process-level defaults from the environment. Secrets are not
// part of probeOptions; the prober keeps its own process-level API key.
func probeOptionsFromParams(params map[string]string, base Options) probeOptions {
	o := probeOptions{
		Threads:         base.Threads,
		Timeout:         base.Timeout,
		FollowRedirects: base.FollowRedirects,
		TechDetect:      base.TechDetect,
		Methods:         append([]string(nil), base.Methods...),
		ASN:             base.ASN,
	}
	if v, ok := params["threads"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			o.Threads = n
		}
	}
	if v, ok := params["timeout_seconds"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			o.Timeout = time.Duration(n) * time.Second
		}
	}
	if v, ok := params["methods"]; ok {
		o.Methods = splitList(v)
	}
	if v, ok := params["follow_redirects"]; ok {
		o.FollowRedirects = v == "true"
	}
	if v, ok := params["tech_detect"]; ok {
		o.TechDetect = v == "true"
	}
	if v, ok := params["asn"]; ok {
		o.ASN = v == "true"
	}
	return o
}

func probeMaxRunTime(params map[string]string, def time.Duration) time.Duration {
	if v, ok := params["max_run_time_seconds"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
