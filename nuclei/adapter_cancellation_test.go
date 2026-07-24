package main

import (
	"context"
	"errors"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type cancellationNucleiRunner struct{ started chan struct{} }

func (r *cancellationNucleiRunner) LoadTargets([]string, bool) {}
func (r *cancellationNucleiRunner) ExecuteCallbackWithCtx(ctx context.Context, _ ...func(*output.ResultEvent)) error {
	close(r.started)
	<-ctx.Done()
	return ctx.Err()
}
func (r *cancellationNucleiRunner) Close() {}

func TestNucleiAdapterPassesCancellation(t *testing.T) {
	old := newNucleiRunner
	t.Cleanup(func() { newNucleiRunner = old })
	fake := &cancellationNucleiRunner{started: make(chan struct{})}
	newNucleiRunner = func(context.Context, ...nuclei.NucleiSDKOptions) (nucleiRunner, error) { return fake, nil }
	e := &nucleiEngine{cfg: config{TemplateDir: t.TempDir()}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := e.Scan(ctx, "https://example.com", nil); done <- err }()
	<-fake.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scan did not return")
	}
}
