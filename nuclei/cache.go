package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// bundleEntry mirrors one element of the data array returned by
// GET /v1/templates/bundle.
type bundleEntry struct {
	ID           string    `json:"id"`
	PresignedURL string    `json:"presigned_url"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// bundleResponse mirrors the control plane's unified response envelope for the
// bundle endpoint. The plugin is a separate module and cannot import the REST
// adapter's Envelope type, so it declares its own minimal view of the fields it
// reads (data on success, error.message on failure).
type bundleResponse struct {
	Success bool          `json:"success"`
	Data    []bundleEntry `json:"data"`
	Error   *bundleError  `json:"error"`
}

// bundleError is the envelope's error payload (a subset of the REST apiError).
type bundleError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// manifestEntry records the cache state of one downloaded file.
type manifestEntry struct {
	UpdatedAt time.Time `json:"updated_at"`
}

// templateCache manages a persistent on-disk cache for nuclei template and
// workflow YAML files. Templates are only re-downloaded when their UpdatedAt
// has advanced since the last successful sync.
//
// Directory layout:
//
//	<dir>/
//	  templates/<id>.yaml   ← scan templates (kind=template)
//	  workflows/<id>.yaml   ← nuclei workflow files (kind=workflow)
//	  .manifest.json        ← tracks per-id UpdatedAt for cache validation
type templateCache struct {
	mu       sync.Mutex
	dir      string
	manifest map[string]manifestEntry
}

func newTemplateCache(dir string) *templateCache {
	return &templateCache{dir: dir, manifest: make(map[string]manifestEntry)}
}

// Load reads the manifest from disk. Idempotent and safe on a fresh directory.
func (c *templateCache) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	path := filepath.Join(c.dir, ".manifest.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	return json.Unmarshal(data, &c.manifest)
}

// Sync downloads entries that are absent or have a newer UpdatedAt than the
// manifest. subdir is "templates" or "workflows".
func (c *templateCache) Sync(ctx context.Context, subdir string, entries []bundleEntry, httpClient *http.Client) error {
	destDir := filepath.Join(c.dir, subdir)
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return fmt.Errorf("create cache subdir: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	downloaded := 0
	for _, e := range entries {
		existing, ok := c.manifest[e.ID]
		if ok && !e.UpdatedAt.After(existing.UpdatedAt) {
			continue // cache hit — skip download
		}
		data, err := fetchOne(ctx, httpClient, e.PresignedURL)
		if err != nil {
			return fmt.Errorf("download %q: %w", e.ID, err)
		}
		dest := filepath.Join(destDir, e.ID+".yaml")
		if err := os.WriteFile(dest, data, 0600); err != nil {
			return fmt.Errorf("write %q: %w", e.ID, err)
		}
		c.manifest[e.ID] = manifestEntry{UpdatedAt: e.UpdatedAt}
		downloaded++
	}

	if downloaded > 0 {
		return c.saveManifest()
	}
	return nil
}

// saveManifest atomically writes the in-memory manifest to disk. Must be called
// with c.mu held.
func (c *templateCache) saveManifest() error {
	if err := os.MkdirAll(c.dir, 0750); err != nil {
		return err
	}
	data, err := json.Marshal(c.manifest)
	if err != nil {
		return err
	}
	path := filepath.Join(c.dir, ".manifest.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// fetchOne downloads a single file from a presigned URL.
func fetchOne(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB per template
}
