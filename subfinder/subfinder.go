package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Finding is one subdomain surfaced by a passive source.
type Finding struct {
	Host   string // discovered subdomain (e.g. "api.example.com")
	Source string // subfinder source that surfaced it (e.g. "crtsh")
}

// enumerator is the port the scanner depends on. The subfinder-backed
// implementation lives below; tests inject a fake.
type enumerator interface {
	Enumerate(ctx context.Context, domain string, stdout, stderr io.Writer) ([]Finding, error)
}

// subfinderEnumerator wraps subfinder's runner so the scanner depends only on
// the enumerator port and not on the SDK directly.
type subfinderEnumerator struct {
	runner *runner.Runner
}

// newSubfinderEnumerator constructs the underlying subfinder runner. We
// deliberately build a runner.Options literal (rather than calling
// runner.ParseOptions) to avoid version-check HTTP calls, banner output, and
// os.Exit on bad flags — none of which belong inside a library boot path.
func newSubfinderEnumerator(cfg config) (*subfinderEnumerator, error) {
	rOpts := &runner.Options{
		Threads:            cfg.Threads,
		Timeout:            int(cfg.Timeout / time.Second),
		MaxEnumerationTime: int(cfg.MaxRunTime / time.Minute),
		Silent:             true,
		All:                cfg.AllSources,
		ProviderConfig:     cfg.ProviderConfig,
		Sources:            cfg.Sources,
		ExcludeSources:     cfg.ExcludeSources,
		Resolvers:          cfg.Resolvers,
		JSON:               true,
		Output:             io.Discard,
		DisableUpdateCheck: true,
	}

	r, err := runner.NewRunner(rOpts)
	if err != nil {
		return nil, fmt.Errorf("subdomain: build subfinder runner: %w", err)
	}
	return &subfinderEnumerator{runner: r}, nil
}

// Enumerate runs a single passive enumeration pass against domain. It uses
// EnumerateSingleDomainWithCtx so subfinder honours ctx cancellation and we
// stay off the higher-level RunEnumeration path.
var gologgerMu sync.Mutex

// gologgerWriter adapts an io.Writer to gologger's level-aware writer API.
// The level-aware path lets scanner log events retain the level assigned by
// gologger while ordinary enumerator output remains an io.Writer stream.
type gologgerWriter struct{ dst io.Writer }

func (w *gologgerWriter) Write(data []byte, level levels.Level) {
	if dst, ok := w.dst.(interface {
		WriteLevel([]byte, levels.Level) (int, error)
	}); ok {
		_, _ = dst.WriteLevel(data, level)
		return
	}
	_, _ = w.dst.Write(data)
}

func (s *subfinderEnumerator) Enumerate(ctx context.Context, domain string, stdout, stderr io.Writer) ([]Finding, error) {
	var buf bytes.Buffer
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	gologgerMu.Lock()
	gologger.DefaultLogger.SetWriter(&gologgerWriter{dst: stderr})
	defer func() {
		// Logger exposes no getter for its current writer. NewCLI is the
		// lifecycle-safe API writer used by the default logger, rather than
		// passing os.Stderr (which is not a gologger writer).
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
		gologgerMu.Unlock()
	}()
	sourceMap, err := s.runner.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.MultiWriter(&buf, stdout)})
	if err != nil {
		return nil, fmt.Errorf("subdomain: subfinder enumerate %q: %w", domain, err)
	}

	// Preferred path: parse the JSONL writer output so we capture per-source
	// attribution exactly as subfinder emitted it.
	findings, parseErr := parseJSONLFindings(buf.Bytes())
	if parseErr == nil && len(findings) > 0 {
		return findings, nil
	}

	// Fallback: build findings from the returned host→sources map.
	return findingsFromSourceMap(sourceMap), nil
}

// jsonSourceResult mirrors the default JSONL shape subfinder emits when
// options.JSON==true and HostIP/CaptureSources are off.
type jsonSourceResult struct {
	Host                string `json:"host"`
	Input               string `json:"input"`
	Source              string `json:"source"`
	WildcardCertificate bool   `json:"wildcard_certificate,omitempty"`
}

func parseJSONLFindings(raw []byte) ([]Finding, error) {
	out := make([]Finding, 0)
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var rec jsonSourceResult
		if err := json.Unmarshal(line, &rec); err != nil {
			// One bad line shouldn't poison the whole result; skip it.
			continue
		}
		host := strings.TrimSpace(rec.Host)
		if host == "" {
			continue
		}
		out = append(out, Finding{Host: host, Source: rec.Source})
	}
	return out, nil
}

// findingsFromSourceMap flattens subfinder's host→set-of-sources return map
// into one Finding per (host, source) pair.
func findingsFromSourceMap(m map[string]map[string]struct{}) []Finding {
	if len(m) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(m))
	for host, sources := range m {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if len(sources) == 0 {
			out = append(out, Finding{Host: host})
			continue
		}
		for src := range sources {
			out = append(out, Finding{Host: host, Source: src})
		}
	}
	return out
}
