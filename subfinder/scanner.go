package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger/levels"
	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// capability is the capability string this plugin advertises. It must match the
// host's scan.CapabilitySubdomain constant and the plugin binary's filename.
const capability = "subdomain"

// scanner implements sdk.Scanner for the subdomain capability using subfinder.
type scanner struct {
	enum    enumerator
	initErr error // deferred construction error, surfaced from Execute
	timeout time.Duration
}

// newScanner parses this plugin's config from the environment and builds the
// subfinder runner. A construction failure (e.g. a malformed provider config)
// is captured and returned from Execute rather than crashing the subprocess, so
// the host gets a clear gRPC error instead of a dead plugin.
func newScanner() *scanner {
	cfg, err := loadConfig()
	if err != nil {
		return &scanner{initErr: err}
	}
	enum, err := newSubfinderEnumerator(cfg)
	return &scanner{enum: enum, initErr: err, timeout: cfg.MaxRunTime}
}

// newWithEnumerator is the test seam.
func newWithEnumerator(enum enumerator, timeout time.Duration) *scanner {
	return &scanner{enum: enum, timeout: timeout}
}

func (s *scanner) Capability(context.Context) (string, error) { return capability, nil }

// Prepare is a no-op for subdomain — only nuclei needs a pre-scan hook.
func (s *scanner) Prepare(context.Context, string) error { return nil }

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
	_ = emit("info", "scan_started", "subdomain scan started", nil)
	if s.initErr != nil {
		_ = emit("error", "scan_failed", "subdomain scan failed", map[string]string{"reason": "initialization"})
		return sdk.Result{}, s.initErr
	}

	start := time.Now()
	domain := strings.TrimSpace(t.Host)
	if domain == "" {
		_ = emit("error", "scan_failed", "subdomain scan failed", map[string]string{"reason": "invalid_target"})
		return sdk.Result{}, errors.New("subdomain: empty target host")
	}

	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	stdout := &lineWriter{emit: func(line string) error {
		return emit("info", "log", line, map[string]string{"stream": "stdout", "line": line})
	}}
	stderr := &lineWriter{level: "info", emitLevel: func(line, level string) error {
		return emit(level, "log", line, map[string]string{"stream": "stderr", "line": line})
	}}
	findings, err := s.enum.Enumerate(ctx, domain, stdout, stderr)
	if flushErr := stdout.Flush(); err == nil {
		err = flushErr
	}
	if flushErr := stderr.Flush(); err == nil {
		err = flushErr
	}
	if err != nil {
		_ = emit("error", "scan_failed", "subdomain scan failed", map[string]string{"reason": "scanner_error"})
		return sdk.Result{}, err
	}

	hosts := make([]string, 0, len(findings))
	bySource := make(map[string][]string)
	for _, f := range findings {
		hosts = append(hosts, f.Host)
		bySource[f.Source] = append(bySource[f.Source], f.Host)
	}

	raw, err := json.Marshal(map[string]any{
		"domain":     domain,
		"subdomains": hosts,
		"by_source":  bySource,
		"count":      len(hosts),
	})
	if err != nil {
		_ = emit("error", "scan_failed", "subdomain scan failed", map[string]string{"reason": "result_encoding"})
		return sdk.Result{}, err
	}
	_ = emit("info", "scan_completed", "subdomain scan completed", map[string]string{"count": strconv.Itoa(len(hosts))})

	return sdk.Result{
		Capability:         capability,
		RawJSON:            raw,
		StartedAtUnixNano:  start.UnixNano(),
		FinishedAtUnixNano: time.Now().UnixNano(),
	}, nil
}

// lineWriter emits complete lines without bufio.Scanner's token limit.
type lineWriter struct {
	buf       strings.Builder
	level     string
	emit      func(string) error
	emitLevel func(string, string) error
}

func (w *lineWriter) Write(p []byte) (int, error) {
	return w.write(p, w.level)
}

func (w *lineWriter) WriteLevel(p []byte, level levels.Level) (int, error) {
	w.level = gologgerLevel(level)
	return w.write(p, gologgerLevel(level))
}

func (w *lineWriter) write(p []byte, level string) (int, error) {
	original := len(p)
	for len(p) > 0 {
		i := strings.IndexByte(string(p), '\n')
		if i < 0 {
			w.buf.WriteString(string(p))
			break
		}
		w.buf.WriteString(string(p[:i]))
		if err := w.emitLine(w.buf.String(), level); err != nil {
			return 0, err
		}
		w.buf.Reset()
		p = p[i+1:]
	}
	return original, nil
}
func (w *lineWriter) Flush() error {
	if w.buf.Len() == 0 {
		return nil
	}
	err := w.emitLine(w.buf.String(), w.level)
	w.buf.Reset()
	return err
}

func (w *lineWriter) emitLine(line, level string) error {
	if w.emitLevel != nil {
		return w.emitLevel(line, level)
	}
	return w.emit(line)
}

func gologgerLevel(level levels.Level) string {
	switch level {
	case levels.LevelFatal:
		return "fatal"
	case levels.LevelError:
		return "error"
	case levels.LevelWarning:
		return "warning"
	case levels.LevelDebug:
		return "debug"
	case levels.LevelVerbose:
		return "verbose"
	default:
		return "info"
	}
}

var _ sdk.Scanner = (*scanner)(nil)
