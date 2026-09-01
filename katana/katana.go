package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	katanatypes "github.com/projectdiscovery/katana/pkg/types"
)

// crawler is the dependency boundary around Katana. It keeps network crawling
// out of scanner unit tests.
type crawler interface {
	Crawl(context.Context, string, crawlOptions, func(string)) error
}

type crawlOptions struct {
	Timeout                time.Duration
	MaxRunTime             time.Duration
	Concurrency            int
	RateLimit              int
	MaxDepth               int
	ScrapeJS               bool
	Strategy               string
	Retries                int
	KnownFiles             string
	MaxDomainPages         int
	FieldScope             string
	IgnoreQueryParams      bool
	FilterSimilar          bool
	FilterSimilarThreshold int
	DisableRedirects       bool
	ExtensionFilter        []string
	DelaySeconds           int
}

type katanaCrawler struct{}

func newKatanaCrawler() crawler { return katanaCrawler{} }

func (katanaCrawler) Crawl(ctx context.Context, target string, opts crawlOptions, onURL func(string)) error {
	var callbackMu sync.Mutex
	// NewCrawlerOptions is a library API, not the CLI option parser. Start from
	// its published defaults so required values such as depth-first traversal,
	// registrable-domain scope, retries, and parallelism are not silently zeroed.
	options := katanatypes.DefaultOptions
	if opts.Timeout > 0 {
		options.Timeout = int(opts.Timeout / time.Second)
	}
	if opts.MaxRunTime > 0 {
		options.CrawlDuration = opts.MaxRunTime
	}
	if opts.Concurrency > 0 {
		options.Concurrency = opts.Concurrency
	}
	if opts.RateLimit > 0 {
		options.RateLimit = opts.RateLimit
	}
	if opts.MaxDepth > 0 {
		options.MaxDepth = opts.MaxDepth
	}
	// Katana's CLI raises depth to three for known-file crawling; reproduce
	// that guard when using its library API directly.
	if opts.KnownFiles != "" && options.MaxDepth < 3 {
		options.MaxDepth = 3
	}
	options.Strategy = opts.Strategy
	options.Retries = opts.Retries
	options.KnownFiles = opts.KnownFiles
	options.MaxDomainPages = opts.MaxDomainPages
	options.FieldScope = opts.FieldScope
	options.IgnoreQueryParams = opts.IgnoreQueryParams
	options.FilterSimilar = opts.FilterSimilar
	options.FilterSimilarThreshold = opts.FilterSimilarThreshold
	options.DisableRedirects = opts.DisableRedirects
	options.ExtensionFilter = append(options.ExtensionFilter[:0], opts.ExtensionFilter...)
	options.Delay = opts.DelaySeconds
	options.ScrapeJSResponses = opts.ScrapeJS
	options.Silent = true
	options.DisableUpdateCheck = true
	options.Context = ctx
	options.OnResult = func(result output.Result) {
		if result.Request == nil || result.Request.URL == "" || onURL == nil {
			return
		}
		callbackMu.Lock()
		onURL(result.Request.URL)
		callbackMu.Unlock()
	}
	crawlerOptions, err := katanatypes.NewCrawlerOptions(&options)
	if err != nil {
		return fmt.Errorf("katana: build crawler options: %w", err)
	}
	defer crawlerOptions.Close()

	engine, err := standard.New(crawlerOptions)
	if err != nil {
		return fmt.Errorf("katana: create crawler: %w", err)
	}
	defer engine.Close()
	if err := engine.Crawl(target); err != nil {
		return fmt.Errorf("katana: crawl %q: %w", target, err)
	}
	return nil
}
