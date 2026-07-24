package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// engine is the scanning port — the nuclei-backed implementation lives here; a
// fake can be injected in tests.
type engine interface {
	Scan(ctx context.Context, target string, params map[string]string) ([]Finding, error)
}

// nucleiEngine is the production implementation. Templates and workflows must
// already be present in TemplateDir — they are synced by Prepare before scans.
type nucleiEngine struct {
	cfg config
}

type nucleiRunner interface {
	LoadTargets([]string, bool)
	ExecuteCallbackWithCtx(context.Context, ...func(*output.ResultEvent)) error
	Close()
}

var newNucleiRunner = func(ctx context.Context, opts ...nuclei.NucleiSDKOptions) (nucleiRunner, error) {
	return nuclei.NewNucleiEngineCtx(ctx, opts...)
}

func newNucleiEngine(cfg config) (*nucleiEngine, error) {
	if cfg.TemplateDir == "" {
		return nil, fmt.Errorf("vuln: VPT_NODE_NUCLEI_TEMPLATE_DIR is required")
	}
	return &nucleiEngine{cfg: cfg}, nil
}

// Scan runs nuclei against target using templates from the persistent cache.
func (n *nucleiEngine) Scan(ctx context.Context, target string, params map[string]string) ([]Finding, error) {
	templateDir := filepath.Join(n.cfg.TemplateDir, "templates")
	workflowDir := filepath.Join(n.cfg.TemplateDir, "workflows")

	ne, err := newNucleiRunner(ctx,
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{templateDir},
			Workflows: []string{workflowDir},
		}),
		nuclei.WithTemplateFilters(filtersFromParams(params)),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           n.cfg.TemplateConcurrency,
			HostConcurrency:               n.cfg.HostConcurrency,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Timeout: n.cfg.NetworkTimeout,
			Retries: n.cfg.NetworkRetries,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("vuln: create nuclei engine: %w", err)
	}
	defer ne.Close()

	ne.LoadTargets([]string{target}, false)

	var (
		mu       sync.Mutex
		findings []Finding
	)
	if err := ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		f := convertEvent(event)
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}); err != nil {
		// ErrNoTemplatesAvailable / ErrNoTargetsAvailable are non-fatal.
		if strings.Contains(err.Error(), "No templates") || strings.Contains(err.Error(), "No targets") {
			return nil, nil
		}
		return nil, fmt.Errorf("vuln: execute: %w", err)
	}
	return findings, nil
}

// filtersFromParams builds nuclei TemplateFilters from scan step params.
func filtersFromParams(params map[string]string) nuclei.TemplateFilters {
	f := nuclei.TemplateFilters{}
	if tags := params["tags"]; tags != "" {
		f.Tags = strings.Split(tags, ",")
	}
	if sev := params["severity"]; sev != "" {
		f.Severity = sev
	}
	if ids := params["ids"]; ids != "" {
		f.IDs = strings.Split(ids, ",")
	}
	return f
}

// convertEvent maps a nuclei ResultEvent to our Finding type.
func convertEvent(event *output.ResultEvent) Finding {
	f := Finding{
		TemplateID:   event.TemplateID,
		TemplateName: event.Info.Name,
		Severity:     event.Info.SeverityHolder.Severity.String(),
		Host:         event.Host,
		Matched:      event.Matched,
		Tags:         event.Info.Tags.ToSlice(),
		Type:         event.Type,
		Description:  event.Info.Description,
		Timestamp:    event.Timestamp,
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now().UTC()
	}
	if f.Tags == nil {
		f.Tags = []string{}
	}
	if event.Info.Classification != nil {
		f.CVEIDs = event.Info.Classification.CVEID.ToSlice()
	}
	if f.CVEIDs == nil {
		f.CVEIDs = []string{}
	}
	return f
}
