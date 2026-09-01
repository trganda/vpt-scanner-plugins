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

const capability = "cloudlist"

type scanner struct {
	enum    cloudEnumerator
	initErr error
	cfg     config
}

func newScanner() *scanner {
	cfg, err := loadConfig()
	if err != nil {
		return &scanner{initErr: err}
	}
	return &scanner{enum: newCloudlistEnumerator(), cfg: cfg}
}

func newWithEnumerator(enum cloudEnumerator, cfg config) *scanner {
	return &scanner{enum: enum, cfg: cfg}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }
func (s *scanner) Prepare(context.Context, string) error      { return nil }
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
	_ = emit("info", "scan_started", "cloud asset enumeration started", nil)
	if s.initErr != nil {
		_ = emit("error", "scan_failed", "cloud asset enumeration failed", map[string]string{"reason": "initialization"})
		return sdk.Result{}, s.initErr
	}

	domain := strings.TrimSpace(t.Host)
	if domain == "" {
		_ = emit("error", "scan_failed", "cloud asset enumeration failed", map[string]string{"reason": "invalid_target"})
		return sdk.Result{}, errors.New("cloudlist: empty target domain")
	}
	opts := cloudOptionsFromParams(t.Params, s.cfg)
	maxRunTime := maxRunTimeFromParams(t.Params, s.cfg.MaxRunTime)
	if maxRunTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, maxRunTime)
		defer cancel()
	}

	started := time.Now()
	assets, failedProviders, err := s.enum.Enumerate(ctx, domain, opts)
	if err != nil {
		_ = emit("error", "scan_failed", "cloud asset enumeration failed", map[string]string{"reason": "scanner_error"})
		return sdk.Result{}, err
	}
	raw, err := json.Marshal(map[string]any{"domain": domain, "assets": assets, "count": len(assets), "failed_providers": failedProviders})
	if err != nil {
		_ = emit("error", "scan_failed", "cloud asset enumeration failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	_ = emit("info", "scan_completed", "cloud asset enumeration completed", map[string]string{"count": strconv.Itoa(len(assets))})
	return sdk.Result{Capability: capability, RawJSON: raw, StartedAtUnixNano: started.UnixNano(), FinishedAtUnixNano: time.Now().UnixNano()}, nil
}

func cloudOptionsFromParams(params map[string]string, cfg config) cloudOptions {
	return cloudOptions{
		ProviderConfig: cfg.ProviderConfig,
		Providers:      splitList(params["providers"]),
		ProviderIDs:    splitList(params["provider_ids"]),
		Services:       splitList(params["services"]),
	}
}

func maxRunTimeFromParams(params map[string]string, def time.Duration) time.Duration {
	if v, ok := params["max_run_time_seconds"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

func splitList(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

var _ sdk.Scanner = (*scanner)(nil)
