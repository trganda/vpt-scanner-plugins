package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	naaburesult "github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// portScanner is the port the scanner depends on. The naabu-backed
// implementation lives below; tests inject a fake.
type portScanner interface {
	Scan(ctx context.Context, host, ports string) ([]PortResult, error)
}

// PortResult is a single open port entry stored in ScanResult.Raw["ports"].
// The json tags must match the legacy in-process executor so the persisted
// JSONB shape is identical.
type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
}

type naabuScanner struct{}

type naabuRunner interface {
	RunEnumeration(context.Context) error
	Close() error
}

var newNaabuRunner = func(opts *runner.Options) (naabuRunner, error) {
	return runner.NewRunner(opts)
}

func newNaabuScanner() *naabuScanner {
	// Silence naabu's global logger so it doesn't emit banners or progress
	// lines. In a plugin this matters doubly: go-plugin uses stdout for the
	// handshake, so any stray stdout write would corrupt it. gologger writes to
	// stderr, which go-plugin tolerates, but we silence it regardless.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	return &naabuScanner{}
}

// Scan performs a TCP connect scan against host on the given ports expression.
// ports may be a top-N shorthand ("100", "1000", "full") or an explicit list
// ("80,443,22") or range ("1-1000"). A new runner is created per call so
// concurrent scans get isolated state.
func (n *naabuScanner) Scan(ctx context.Context, host, ports string) ([]PortResult, error) {
	var mu sync.Mutex
	var found []PortResult

	opts := runner.Options{
		Host:               goflags.StringSlice{host},
		ScanType:           runner.ConnectScan,
		Silent:             true,
		NoColor:            true,
		DisableUpdateCheck: true,
		DisableStdout:      true,
		OnResult: func(hr *naaburesult.HostResult) {
			mu.Lock()
			defer mu.Unlock()
			for _, p := range hr.Ports {
				found = append(found, PortResult{
					Port:     p.Port,
					Protocol: p.Protocol.String(),
				})
			}
		},
	}
	// naabu distinguishes between a built-in top-N list (TopPorts) and an
	// explicit port expression (Ports). Route accordingly.
	switch ports {
	case "100", "1000", "full":
		opts.TopPorts = ports
	default:
		opts.Ports = ports
	}

	r, err := newNaabuRunner(&opts)
	if err != nil {
		return nil, fmt.Errorf("portscan: build naabu runner: %w", err)
	}
	defer r.Close()

	if err := r.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("portscan: naabu scan %q: %w", host, err)
	}
	return found, nil
}
