package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

const capability = "katana"

type scanner struct {
	crawler crawler
	initErr error
	cfg     config
}

func newScanner() *scanner {
	cfg, err := loadConfig()
	if err != nil {
		return &scanner{initErr: err}
	}
	return &scanner{crawler: newKatanaCrawler(), cfg: cfg}
}

func newWithCrawler(c crawler, cfg config) *scanner { return &scanner{crawler: c, cfg: cfg} }

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
	_ = emit("info", "scan_started", "web crawl started", nil)
	if s.initErr != nil {
		_ = emit("error", "scan_failed", "web crawl failed", map[string]string{"reason": "initialization"})
		return sdk.Result{}, s.initErr
	}

	target := strings.TrimSpace(t.Host)
	if target == "" {
		_ = emit("error", "scan_failed", "web crawl failed", map[string]string{"reason": "invalid_target"})
		return sdk.Result{}, errors.New("katana: empty target URL")
	}
	opts := crawlOptionsFromParams(t.Params, s.cfg)
	if opts.MaxRunTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.MaxRunTime)
		defer cancel()
	}

	started := time.Now()
	urls := make([]string, 0)
	seen := make(map[string]struct{})
	var urlsMu sync.Mutex
	err := s.crawler.Crawl(ctx, target, opts, func(url string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		urlsMu.Lock()
		defer urlsMu.Unlock()
		if _, ok := seen[url]; ok {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	})
	if err != nil {
		_ = emit("error", "scan_failed", "web crawl failed", map[string]string{"reason": "scanner_error"})
		return sdk.Result{}, err
	}

	raw, err := json.Marshal(map[string]any{"target": target, "urls": urls, "count": len(urls)})
	if err != nil {
		_ = emit("error", "scan_failed", "web crawl failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	_ = emit("info", "scan_completed", "web crawl completed", map[string]string{"count": strconv.Itoa(len(urls))})
	return sdk.Result{Capability: capability, RawJSON: raw, StartedAtUnixNano: started.UnixNano(), FinishedAtUnixNano: time.Now().UnixNano()}, nil
}

func crawlOptionsFromParams(params map[string]string, cfg config) crawlOptions {
	o := crawlOptions{
		Timeout:                cfg.Timeout,
		MaxRunTime:             cfg.MaxRunTime,
		Concurrency:            cfg.Concurrency,
		RateLimit:              cfg.RateLimit,
		MaxDepth:               cfg.MaxDepth,
		ScrapeJS:               cfg.ScrapeJS,
		Strategy:               "depth-first",
		Retries:                1,
		MaxDomainPages:         1000,
		FieldScope:             "rdn",
		FilterSimilarThreshold: 10,
	}
	if n, ok := positiveIntParam(params, "timeout_seconds"); ok {
		o.Timeout = time.Duration(n) * time.Second
	}
	if n, ok := positiveIntParam(params, "max_run_time_seconds"); ok {
		o.MaxRunTime = time.Duration(n) * time.Second
	}
	if n, ok := positiveIntParam(params, "concurrency"); ok {
		o.Concurrency = n
	}
	if n, ok := positiveIntParam(params, "rate_limit"); ok {
		o.RateLimit = n
	}
	if n, ok := positiveIntParam(params, "max_depth"); ok {
		o.MaxDepth = n
	}
	if v, ok := params["scrape_js"]; ok {
		o.ScrapeJS = v == "true"
	}
	if v, ok := params["strategy"]; ok && (v == "depth-first" || v == "breadth-first") {
		o.Strategy = v
	}
	if n, ok := nonNegativeIntParam(params, "retries"); ok {
		o.Retries = n
	}
	if v, ok := params["known_files"]; ok {
		switch v {
		case "all", "robotstxt", "sitemapxml":
			o.KnownFiles = v
		case "none":
			o.KnownFiles = ""
		}
	}
	if n, ok := positiveIntParam(params, "max_domain_pages"); ok {
		o.MaxDomainPages = n
	}
	if v, ok := params["field_scope"]; ok && (v == "rdn" || v == "fqdn") {
		o.FieldScope = v
	}
	if v, ok := params["ignore_query_params"]; ok {
		o.IgnoreQueryParams = v == "true"
	}
	if v, ok := params["filter_similar"]; ok {
		o.FilterSimilar = v == "true"
	}
	if n, ok := positiveIntParam(params, "filter_similar_threshold"); ok {
		o.FilterSimilarThreshold = n
	}
	if v, ok := params["disable_redirects"]; ok {
		o.DisableRedirects = v == "true"
	}
	if v, ok := params["extension_filter"]; ok {
		o.ExtensionFilter = splitList(v)
	}
	if n, ok := nonNegativeIntParam(params, "delay_seconds"); ok {
		o.DelaySeconds = n
	}
	return o
}

func positiveIntParam(params map[string]string, name string) (int, bool) {
	n, ok := nonNegativeIntParam(params, name)
	return n, ok && n > 0
}

func nonNegativeIntParam(params map[string]string, name string) (int, bool) {
	v, ok := params[name]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	out := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

var _ sdk.Scanner = (*scanner)(nil)
