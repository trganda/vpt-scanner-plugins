package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

type fakeCrawler struct {
	target string
	opts   crawlOptions
	urls   []string
	err    error
}

func (f *fakeCrawler) Crawl(_ context.Context, target string, opts crawlOptions, onURL func(string)) error {
	f.target, f.opts = target, opts
	for _, url := range f.urls {
		onURL(url)
	}
	return f.err
}

func TestScannerCrawlsAndReturnsURLs(t *testing.T) {
	fake := &fakeCrawler{urls: []string{"https://app.example.test/", "https://app.example.test/a", "https://app.example.test/a"}}
	s := newWithCrawler(fake, config{Timeout: time.Second, MaxRunTime: time.Minute, Concurrency: 2, RateLimit: 3, MaxDepth: 4})
	result, err := s.Execute(context.Background(), sdk.Target{Host: "https://app.example.test/", Params: map[string]string{
		"max_depth": "2", "scrape_js": "true", "strategy": "breadth-first", "retries": "3", "known_files": "all",
		"max_domain_pages": "17", "field_scope": "fqdn", "ignore_query_params": "true", "filter_similar": "true",
		"filter_similar_threshold": "4", "disable_redirects": "true", "extension_filter": "png, css", "delay_seconds": "2",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if fake.target != "https://app.example.test/" || fake.opts.MaxDepth != 2 || !fake.opts.ScrapeJS || fake.opts.Strategy != "breadth-first" || fake.opts.Retries != 3 || fake.opts.KnownFiles != "all" || fake.opts.MaxDomainPages != 17 || fake.opts.FieldScope != "fqdn" || !fake.opts.IgnoreQueryParams || !fake.opts.FilterSimilar || fake.opts.FilterSimilarThreshold != 4 || !fake.opts.DisableRedirects || fake.opts.DelaySeconds != 2 || len(fake.opts.ExtensionFilter) != 2 || fake.opts.ExtensionFilter[1] != "css" {
		t.Fatalf("unexpected crawl invocation: %#v", fake)
	}
	var raw struct {
		URLs []string `json:"urls"`
	}
	if err := json.Unmarshal(result.RawJSON, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.URLs) != 2 {
		t.Fatalf("expected deduplicated URLs, got %#v", raw.URLs)
	}
}

func TestKatanaOutputMapperSkipsInvalidURLs(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"urls": []string{"https://app.example.test/a", "not a url"}})
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := katanaOutputMapper(sdk.Target{}, sdk.Result{RawJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(outputs) != 1 || len(outputs[0].Values) != 1 || outputs[0].Values[0].String() != "https://app.example.test/a" {
		t.Fatalf("unexpected outputs: %#v", outputs)
	}
}
