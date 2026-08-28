package main

import (
	"context"
	"testing"
	"time"
)

func TestPortSetGateSharesSamePortSet(t *testing.T) {
	g := newPortSetGate()
	rel1, err := g.acquire(context.Background(), "80,443")
	if err != nil {
		t.Fatal(err)
	}
	rel2, err := g.acquire(context.Background(), "80,443")
	if err != nil {
		t.Fatal(err)
	}
	rel1()
	rel2()
}

func TestPortSetGateSerializesDifferentPortSet(t *testing.T) {
	g := newPortSetGate()
	rel1, err := g.acquire(context.Background(), "80")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		rel2, err := g.acquire(context.Background(), "8080")
		if err == nil {
			rel2()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("second acquire should block until first releases, got %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	rel1()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second acquire did not proceed after release")
	}
}

func TestPortSetGateCancellation(t *testing.T) {
	g := newPortSetGate()
	rel1, err := g.acquire(context.Background(), "80")
	if err != nil {
		t.Fatal(err)
	}
	defer rel1()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.acquire(ctx, "8080"); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
