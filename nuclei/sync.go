package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// syncer downloads and refreshes the persistent nuclei template cache from the
// control plane's bundle endpoint. It is the relocated body of the old in-process
// VulnSyncActivities, minus the Temporal heartbeat (which stays host-side, since
// a plugin has no Temporal context). The node JWT arrives as a Prepare argument
// rather than a func, because it can't cross the gRPC boundary as a closure.
type syncer struct {
	bundleURL   string
	templateDir string
	httpClient  *http.Client
}

func newSyncer(cfg config) *syncer {
	return &syncer{
		bundleURL:   cfg.BundleURL,
		templateDir: cfg.TemplateDir,
		httpClient:  &http.Client{Timeout: 60 * time.Second},
	}
}

// Sync refreshes scan templates and workflow files into the persistent cache,
// skipping any whose UpdatedAt has not advanced since the last sync. authToken
// is the control-plane-issued node JWT (GET /v1/templates/bundle is gated by
// NodeAuth); an empty token omits the Authorization header.
func (s *syncer) Sync(ctx context.Context, authToken string) error {
	cache := newTemplateCache(s.templateDir)
	if err := cache.Load(); err != nil {
		return fmt.Errorf("load template cache: %w", err)
	}

	templateEntries, err := s.fetchBundle(ctx, "template", authToken)
	if err != nil {
		return fmt.Errorf("fetch template bundle: %w", err)
	}
	if err := cache.Sync(ctx, "templates", templateEntries, s.httpClient); err != nil {
		return fmt.Errorf("sync templates: %w", err)
	}

	workflowEntries, err := s.fetchBundle(ctx, "workflow", authToken)
	if err != nil {
		return fmt.Errorf("fetch workflow bundle: %w", err)
	}
	if err := cache.Sync(ctx, "workflows", workflowEntries, s.httpClient); err != nil {
		return fmt.Errorf("sync workflows: %w", err)
	}

	return nil
}

// fetchBundle calls GET <BundleURL>?kind=<kind> and returns the bundle entries.
func (s *syncer) fetchBundle(ctx context.Context, kind, authToken string) ([]bundleEntry, error) {
	u, err := url.Parse(s.bundleURL)
	if err != nil {
		return nil, fmt.Errorf("parse bundle URL: %w", err)
	}
	q := u.Query()
	q.Set("kind", kind)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50 MB cap
	if err != nil {
		return nil, err
	}
	var env bundleResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode bundle response: %w", err)
	}
	if !env.Success {
		if env.Error != nil && env.Error.Message != "" {
			return nil, fmt.Errorf("bundle endpoint error: %s", env.Error.Message)
		}
		return nil, fmt.Errorf("bundle endpoint returned an unsuccessful response")
	}
	return env.Data, nil
}
