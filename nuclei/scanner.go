package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// capability is the capability string this plugin advertises. It must match the
// host's scan.CapabilityVuln constant and the plugin binary's filename.
const capability = "vuln"

// scanner implements sdk.Scanner for the vuln capability using nuclei. Unlike
// the other tools it implements a meaningful Prepare: the pre-scan template
// sync (host SyncVulnTemplatesActivity delegates to it over gRPC).
type scanner struct {
	eng     engine
	syncer  *syncer
	initErr error // deferred construction error, surfaced from Execute/Prepare
}

func newScanner() *scanner {
	cfg, err := loadConfig()
	if err != nil {
		return &scanner{initErr: err}
	}
	eng, err := newNucleiEngine(cfg)
	if err != nil {
		return &scanner{initErr: err}
	}
	return &scanner{eng: eng, syncer: newSyncer(cfg)}
}

// newWithEngine is the test seam.
func newWithEngine(eng engine) *scanner {
	return &scanner{eng: eng}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }

// Prepare syncs the persistent template cache before scans run. authToken is
// the node JWT the host read from its token holder at call time.
func (s *scanner) Prepare(ctx context.Context, authToken string) error {
	if s.initErr != nil {
		return s.initErr
	}
	if s.syncer == nil {
		return errors.New("vuln: template syncer not configured")
	}
	return s.syncer.Sync(ctx, authToken)
}

func (s *scanner) Execute(ctx context.Context, t sdk.Target) (sdk.Result, error) {
	return s.ExecuteStream(ctx, t, nil)
}

func (s *scanner) ExecuteStream(ctx context.Context, t sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	seq := int64(0)
	emit := func(level, typ, message string, fields map[string]string) error {
		seq++
		if sink == nil {
			return nil
		}
		e := sdk.NewEvent(level, typ, message, fields)
		e.Sequence = seq
		return sink(e)
	}
	_ = emit("info", "scan_started", "vulnerability scan started", nil)
	if s.initErr != nil {
		_ = emit("error", "scan_failed", "vulnerability scan failed", map[string]string{"reason": "initialization"})
		return sdk.Result{}, s.initErr
	}

	start := time.Now()
	findings, err := s.eng.Scan(ctx, strings.TrimSpace(t.Host), t.Params)
	if err != nil {
		_ = emit("error", "scan_failed", "vulnerability scan failed", map[string]string{"reason": "scanner_error"})
		return sdk.Result{}, err
	}

	raw, err := json.Marshal(map[string]any{
		"host":     t.Host,
		"findings": findings,
		"count":    len(findings),
	})
	if err != nil {
		_ = emit("error", "scan_failed", "vulnerability scan failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	_ = emit("info", "scan_completed", "vulnerability scan completed", map[string]string{"count": strconv.Itoa(len(findings))})

	return sdk.Result{
		Capability:         capability,
		RawJSON:            raw,
		StartedAtUnixNano:  start.UnixNano(),
		FinishedAtUnixNano: time.Now().UnixNano(),
	}, nil
}

var _ sdk.Scanner = (*scanner)(nil)
