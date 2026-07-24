package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type cancellationSubfinderRunner struct{ started chan struct{} }

func (r *cancellationSubfinderRunner) EnumerateSingleDomainWithCtx(ctx context.Context, _ string, _ []io.Writer) (map[string]map[string]struct{}, error) {
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSubfinderAdapterPassesCancellation(t *testing.T) {
	old := newSubfinderRunner
	t.Cleanup(func() { newSubfinderRunner = old })
	fake := &cancellationSubfinderRunner{started: make(chan struct{})}
	newSubfinderRunner = func(*runner.Options) (subfinderRunner, error) { return fake, nil }

	e := &subfinderEnumerator{runner: fake}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := e.Enumerate(ctx, "example.com", nil, nil); done <- err }()
	<-fake.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("enumeration did not return")
	}
}
