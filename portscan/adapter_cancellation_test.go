package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type cancellationNaabuRunner struct {
	ctx      context.Context
	started  chan struct{}
	canceled chan struct{}
}

func (r *cancellationNaabuRunner) RunEnumeration(ctx context.Context) error {
	r.ctx = ctx
	close(r.started)
	<-ctx.Done()
	close(r.canceled)
	return ctx.Err()
}
func (r *cancellationNaabuRunner) Close() error { return nil }

func TestNaabuScannerPassesCancellation(t *testing.T) {
	old := newNaabuRunner
	t.Cleanup(func() { newNaabuRunner = old })
	fake := &cancellationNaabuRunner{started: make(chan struct{}), canceled: make(chan struct{})}
	newNaabuRunner = func(*runner.Options) (naabuRunner, error) { return fake, nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := (&naabuScanner{}).Scan(ctx, "example.com", "80"); done <- err }()
	<-fake.started
	cancel()
	select {
	case <-fake.canceled:
	case <-time.After(time.Second):
		t.Fatal("naabu did not observe cancellation")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scan did not return")
	}
}
