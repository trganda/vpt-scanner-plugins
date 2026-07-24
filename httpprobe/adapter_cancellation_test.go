package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/runner"
)

type cancellationHTTPXRunner struct {
	started, interrupted, release, returned, closed chan struct{}
	releaseOnce, closeOnce                          sync.Once
}

func (r *cancellationHTTPXRunner) RunEnumeration() {
	close(r.started)
	<-r.release
	close(r.returned)
}
func (r *cancellationHTTPXRunner) Interrupt() {
	select {
	case <-r.interrupted:
	default:
		close(r.interrupted)
	}
}
func (r *cancellationHTTPXRunner) Close() { r.closeOnce.Do(func() { close(r.closed) }) }
func (r *cancellationHTTPXRunner) releaseEnumeration() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func newCancellationRunner() *cancellationHTTPXRunner {
	return &cancellationHTTPXRunner{
		started: make(chan struct{}), interrupted: make(chan struct{}),
		release: make(chan struct{}), returned: make(chan struct{}), closed: make(chan struct{}),
	}
}

func installCancellationRunner(t *testing.T, fake *cancellationHTTPXRunner) {
	old := newHTTPXRunner
	t.Cleanup(func() { newHTTPXRunner = old })
	newHTTPXRunner = func(*runner.Options) (httpxRunner, error) { return fake, nil }
}

func TestHTTPXAdapterCancellationWaitsForImmediateUnwind(t *testing.T) {
	fake := newCancellationRunner()
	installCancellationRunner(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := (&httpxProber{}).Probe(ctx, "example.com", "80"); done <- err }()
	<-fake.started
	cancel()
	fake.releaseEnumeration()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("httpx did not return after enumeration unwind")
	}
	select {
	case <-fake.returned:
	case <-time.After(time.Second):
		t.Fatal("fake enumeration did not unwind after Interrupt")
	}
	select {
	case <-fake.closed:
	case <-time.After(time.Second):
		t.Fatal("runner was not closed after enumeration returned")
	}
}

func TestHTTPXAdapterCancellationWaitsForDelayedUnwind(t *testing.T) {
	fake := newCancellationRunner()
	installCancellationRunner(t, fake)
	t.Cleanup(fake.releaseEnumeration)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := (&httpxProber{}).Probe(ctx, "example.com", "80"); done <- err }()
	<-fake.started
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned before unwind: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	fake.releaseEnumeration()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not return after delayed unwind")
	}
}

func TestHTTPXAdapterCancellationReturnsAfterGraceForStalledRunner(t *testing.T) {
	fake := newCancellationRunner()
	installCancellationRunner(t, fake)
	t.Cleanup(fake.releaseEnumeration)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := (&httpxProber{}).Probe(ctx, "example.com", "80"); done <- err }()
	<-fake.started
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * httpxCancellationGracePeriod):
		t.Fatal("cancellation did not respect grace deadline")
	}
	if elapsed := time.Since(start); elapsed < httpxCancellationGracePeriod/2 {
		t.Fatalf("returned too early: %s", elapsed)
	}
	// Let the enumeration goroutine finish so this test does not leak it or
	// leave the global gate held for subsequent tests.
	fake.releaseEnumeration()
	select {
	case <-fake.closed:
	case <-time.After(time.Second):
		t.Fatal("stalled runner did not finish cleanup")
	}
}

func TestHTTPXAdapterCancelledCallDoesNotWaitForStalledGate(t *testing.T) {
	first := newCancellationRunner()
	installCancellationRunner(t, first)
	t.Cleanup(first.releaseEnumeration)
	firstDone := make(chan error, 1)
	go func() {
		_, err := (&httpxProber{}).Probe(context.Background(), "first.example", "80")
		firstDone <- err
	}()
	<-first.started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := (&httpxProber{}).Probe(ctx, "second.example", "80")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled gate wait took too long: %s", elapsed)
	}

	first.releaseEnumeration()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first runner did not finish cleanup")
	}
}
