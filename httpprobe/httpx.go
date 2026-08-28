package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	customport "github.com/projectdiscovery/httpx/common/customports"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// maxBodyBytes caps the response body httpx reads and saves per probe. The
// (possibly-truncated) body is base64-encoded before it enters ProbeResult so
// the result payload stays small and binary-safe.
const maxBodyBytes = 64 * 1024

// portSetGate serialises probes only while the active custom port set changes.
// httpx reads the package-level customport.Ports map during enumeration, so
// probes that share the current port set may run concurrently (read-only use of
// the map), while a probe with a different port set waits until the active set
// is idle before reloading the global map. The wait is context-aware so
// cancellation never blocks behind a stalled probe.
type portSetGate struct {
	mu     sync.Mutex
	active string
	refs   int
	idle   chan struct{}
}

func newPortSetGate() *portSetGate {
	g := &portSetGate{}
	g.idle = make(chan struct{})
	close(g.idle)
	return g
}

var httpxPortSetGate = newPortSetGate()

// acquire loads ports into customport.Ports when necessary and returns a
// release func. Concurrent callers with the same ports share the loaded map;
// callers with a different ports value wait for the active set to drain.
func (g *portSetGate) acquire(ctx context.Context, ports string) (func(), error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		g.mu.Lock()
		if g.refs == 0 {
			customport.Ports = map[int]string{}
			cp := customport.CustomPorts{}
			if err := cp.Set(ports); err != nil {
				g.mu.Unlock()
				return nil, err
			}
			g.active = ports
			g.refs = 1
			g.idle = make(chan struct{})
			g.mu.Unlock()
			return g.release, nil
		}
		if g.active == ports {
			g.refs++
			g.mu.Unlock()
			return g.release, nil
		}
		idle := g.idle
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-idle:
		}
	}
}

func (g *portSetGate) release() {
	g.mu.Lock()
	g.refs--
	if g.refs == 0 {
		g.active = ""
		close(g.idle)
	}
	g.mu.Unlock()
}

const httpxCancellationGracePeriod = 250 * time.Millisecond

// ProbeResult is one URL's worth of HTTP metadata, stored in
// ScanResult.Raw["probes"]. The JSON shape here is the cross-process contract
// the host's result processor (rawProbe) decodes against — field tags must stay
// in sync with internal/adapter/temporal/result_processor.go.
type ProbeResult struct {
	URL           string   `json:"url"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	WebServer     string   `json:"web_server,omitempty"`
	ContentLength int      `json:"content_length"`
	Technologies  []string `json:"technologies,omitempty"`
	ResponseTime  string   `json:"response_time,omitempty"`
	FinalURL      string   `json:"final_url,omitempty"`

	CDNName         string         `json:"cdn_name,omitempty"`
	CDNType         string         `json:"cdn_type,omitempty"`
	SNI             string         `json:"sni,omitempty"`
	ContentType     string         `json:"content_type,omitempty"`
	Method          string         `json:"method,omitempty"`
	ResponseBody    string         `json:"response_body,omitempty"`
	ResponseHeaders map[string]any `json:"response_headers,omitempty"`
	A               []string       `json:"a,omitempty"`
	AAAA            []string       `json:"aaaa,omitempty"`
	TLS             *TLSData       `json:"tls,omitempty"`

	ASNNumber  string   `json:"asn_number,omitempty"`
	ASNName    string   `json:"asn_name,omitempty"`
	ASNCountry string   `json:"asn_country,omitempty"`
	ASNRange   []string `json:"asn_range,omitempty"`
}

// prober is the port the scanner depends on. The httpx-backed implementation
// lives below; tests inject a fake.
type prober interface {
	Probe(ctx context.Context, host, ports string, opts probeOptions) ([]ProbeResult, error)
}

// probeOptions carries per-call HTTP probing tuning. All fields are fully
// resolved by the scanner from process defaults plus step params; secrets such
// as the PDCP API key intentionally remain process-level only.
type probeOptions struct {
	Threads         int
	Timeout         time.Duration
	FollowRedirects bool
	TechDetect      bool
	Methods         []string
	ASN             bool
}

// httpxProber wraps the projectdiscovery httpx SDK. The underlying runner is
// rebuilt per call (concurrent activities can't share runner state).
type httpxProber struct {
	opts Options
}

type httpxRunner interface {
	RunEnumeration()
	Interrupt()
	Close()
}

var newHTTPXRunner = func(opts *runner.Options) (httpxRunner, error) {
	return runner.New(opts)
}

// newHTTPXProber silences gologger eagerly so httpx's banner / progress lines
// never reach stderr, and (in a plugin) never corrupt the go-plugin handshake
// on stdout.
func newHTTPXProber(opts Options) (*httpxProber, error) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	// runner.New does not apply the CLI-only PdcpAuth setup, while its ASN
	// lookup reads asnmap's package-level key directly.
	if opts.PdcpAPIKey != "" {
		asnmap.PDCPApiKey = opts.PdcpAPIKey
	}
	return &httpxProber{opts: opts}, nil
}

// Probe fans the configured options into a fresh runner.Options for this
// (host, ports) pair, runs the enumeration, and collects per-URL results from
// the OnResult callback. Per-call overrides are layered over the process-level
// defaults held by the prober; the PDCP API key always stays process-level.
func (h *httpxProber) Probe(ctx context.Context, host, ports string, o probeOptions) ([]ProbeResult, error) {
	releaseGate, err := httpxPortSetGate.acquire(ctx, ports)
	if err != nil {
		return nil, fmt.Errorf("httpprobe: parse ports %q: %w", ports, err)
	}
	var gateReleased sync.Once
	releaseOnce := func() {
		gateReleased.Do(releaseGate)
	}

	opts := h.opts
	opts.Threads = o.Threads
	opts.Timeout = o.Timeout
	opts.FollowRedirects = o.FollowRedirects
	opts.TechDetect = o.TechDetect
	opts.ASN = o.ASN
	opts.Methods = append([]string(nil), o.Methods...)

	// The port set is already loaded into customport.Ports by acquire. The
	// runner reads that global during enumeration; CustomPorts here keeps the
	// raw value for httpx's options surface (validation already happened).
	cp := customport.CustomPorts{ports}

	var (
		mu      sync.Mutex
		results []ProbeResult
	)

	rOpts := &runner.Options{
		InputTargetHost:    goflags.StringSlice{host},
		CustomPorts:        cp,
		Threads:            opts.Threads,
		Timeout:            int(opts.Timeout / time.Second),
		FollowRedirects:    opts.FollowRedirects,
		TechDetect:         opts.TechDetect,
		Methods:            strings.Join(opts.Methods, ","),
		Silent:             true,
		NoColor:            true,
		DisableUpdateCheck: true,
		DisableStdout:      true,
		StatusCode:         true,
		ContentLength:      true,
		ExtractTitle:       true,
		OutputServerHeader: true,
		OutputResponseTime: true,

		TLSGrab:                   true,
		OutputCDN:                 "true",
		OutputContentType:         true,
		OutputIP:                  true,
		ResponseHeadersInStdout:   true,
		ResponseInStdout:          true,
		MaxResponseBodySizeToRead: maxBodyBytes,
		MaxResponseBodySizeToSave: maxBodyBytes,

		Asn:      opts.ASN,
		PdcpAuth: opts.PdcpAPIKey,

		OnResult: func(r runner.Result) {
			if r.Err != nil || r.Failed {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			var body string
			if r.ResponseBody != "" {
				raw := r.ResponseBody
				if len(raw) > maxBodyBytes {
					raw = raw[:maxBodyBytes]
				}
				body = base64.StdEncoding.EncodeToString([]byte(raw))
			}
			var asnNumber, asnName, asnCountry string
			var asnRange []string
			if r.ASN != nil {
				asnNumber = r.ASN.AsNumber
				asnName = r.ASN.AsName
				asnCountry = r.ASN.AsCountry
				asnRange = append([]string(nil), r.ASN.AsRange...)
			}
			results = append(results, ProbeResult{
				URL:             r.URL,
				Scheme:          r.Scheme,
				StatusCode:      r.StatusCode,
				Title:           r.Title,
				WebServer:       r.WebServer,
				ContentLength:   r.ContentLength,
				Technologies:    append([]string(nil), r.Technologies...),
				ResponseTime:    r.ResponseTime,
				FinalURL:        r.FinalURL,
				CDNName:         r.CDNName,
				CDNType:         r.CDNType,
				SNI:             r.SNI,
				ContentType:     r.ContentType,
				Method:          r.Method,
				ResponseBody:    body,
				ResponseHeaders: r.ResponseHeaders,
				A:               append([]string(nil), r.A...),
				AAAA:            append([]string(nil), r.AAAA...),
				TLS:             mapTLS(r.TLSData),
				ASNNumber:       asnNumber,
				ASNName:         asnName,
				ASNCountry:      asnCountry,
				ASNRange:        asnRange,
			})
		},
	}

	r, err := newHTTPXRunner(rOpts)
	if err != nil {
		releaseOnce()
		return nil, fmt.Errorf("httpprobe: build httpx runner: %w", err)
	}
	// RunEnumeration() doesn't take a context. Honour ctx cancellation by
	// running enumeration in a goroutine and Interrupt()-ing it when the
	// caller's context fires. Cleanup is deliberately owned by the enumeration
	// goroutine: closing the runner here could race with httpx still unwinding.
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunEnumeration()
		r.Close()
		releaseOnce()
	}()

	select {
	case <-ctx.Done():
		r.Interrupt()
		grace := time.NewTimer(httpxCancellationGracePeriod)
		defer grace.Stop()
		select {
		case <-done:
		case <-grace.C:
		}
		return nil, ctx.Err()
	case <-done:
	}

	return results, nil
}

// mapTLS distils httpx's TLS-grab output (tlsx clients.Response) into the
// curated, SDK-free TLSData persisted as JSONB. Returns nil for a plaintext
// probe or a failed grab.
func mapTLS(t *clients.Response) *TLSData {
	if t == nil {
		return nil
	}
	out := &TLSData{
		Version:  t.Version,
		Cipher:   t.Cipher,
		SNI:      t.ServerName,
		JA3Hash:  t.Ja3Hash,
		JA3SHash: t.Ja3sHash,
		JARMHash: t.JarmHash,
	}
	if c := t.CertificateResponse; c != nil {
		out.NotBefore = c.NotBefore
		out.NotAfter = c.NotAfter
		out.SubjectCN = c.SubjectCN
		out.SubjectOrg = append([]string(nil), c.SubjectOrg...)
		out.SubjectAN = append([]string(nil), c.SubjectAN...)
		out.IssuerCN = c.IssuerCN
		out.IssuerOrg = append([]string(nil), c.IssuerOrg...)
		out.Serial = c.Serial
		out.FingerprintSHA256 = c.FingerprintHash.SHA256
		out.SelfSigned = c.SelfSigned
		out.Expired = c.Expired
		out.MisMatched = c.MisMatched
		out.WildcardCert = c.WildCardCert
	}
	return out
}
