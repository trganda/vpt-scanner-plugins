package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

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

// httpxGlobalMu serialises Probe() calls across the whole process. httpx stores
// its custom-port set in a package-level map (customport.Ports) which the
// runner reads during enumeration — two concurrent Probe() calls would race on
// that map. In a single-tool plugin process this is rarely contended, but the
// guard is kept since the global is httpx-internal.
var httpxGlobalMu sync.Mutex

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
	Probe(ctx context.Context, host, ports string) ([]ProbeResult, error)
}

// httpxProber wraps the projectdiscovery httpx SDK. The underlying runner is
// rebuilt per call (concurrent activities can't share runner state).
type httpxProber struct {
	opts Options
}

// newHTTPXProber silences gologger eagerly so httpx's banner / progress lines
// never reach stderr, and (in a plugin) never corrupt the go-plugin handshake
// on stdout.
func newHTTPXProber(opts Options) (*httpxProber, error) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	return &httpxProber{opts: opts}, nil
}

// Probe fans the configured options into a fresh runner.Options for this
// (host, ports) pair, runs the enumeration, and collects per-URL results from
// the OnResult callback.
func (h *httpxProber) Probe(ctx context.Context, host, ports string) ([]ProbeResult, error) {
	httpxGlobalMu.Lock()
	defer httpxGlobalMu.Unlock()

	// Reset the global before populating it so we don't see ports from a prior
	// caller. CustomPorts.Set() merges into customport.Ports.
	customport.Ports = map[int]string{}
	cp := customport.CustomPorts{}
	if err := cp.Set(ports); err != nil {
		return nil, fmt.Errorf("httpprobe: parse ports %q: %w", ports, err)
	}

	var (
		mu      sync.Mutex
		results []ProbeResult
	)

	rOpts := &runner.Options{
		InputTargetHost:    goflags.StringSlice{host},
		CustomPorts:        cp,
		Threads:            h.opts.Threads,
		Timeout:            int(h.opts.Timeout / time.Second),
		FollowRedirects:    h.opts.FollowRedirects,
		TechDetect:         h.opts.TechDetect,
		Methods:            strings.Join(h.opts.Methods, ","),
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

		Asn:      h.opts.ASN,
		PdcpAuth: h.opts.PdcpAPIKey,

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

	r, err := runner.New(rOpts)
	if err != nil {
		return nil, fmt.Errorf("httpprobe: build httpx runner: %w", err)
	}
	defer r.Close()

	// RunEnumeration() doesn't take a context. Honour ctx cancellation by
	// running enumeration in a goroutine and Interrupt()-ing it when the
	// caller's context fires.
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunEnumeration()
	}()

	select {
	case <-ctx.Done():
		r.Interrupt()
		<-done
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
