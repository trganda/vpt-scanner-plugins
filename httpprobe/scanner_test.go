package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/trganda/vpt-scanner-plugins/sdk"
)

// fakeProber is a double for the prober port so these tests don't drag the
// httpx SDK or live network into the unit suite.
type fakeProber struct {
	probes   []ProbeResult
	err      error
	calls    int
	gotHost  string
	gotPorts string
	block    bool
	started  chan struct{}
}

func (f *fakeProber) ProbeBatch(ctx context.Context, targets []sdk.Target) ([]sdk.Result, error) {
	f.calls++
	if len(targets) > 0 {
		f.gotHost = targets[0].Host
		f.gotPorts = targets[0].Params["ports"]
		if f.gotPorts == "" {
			f.gotPorts = "80,443"
		}
	}
	if f.block {
		if f.started != nil {
			close(f.started)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	out := make([]sdk.Result, len(targets))
	for i, target := range targets {
		raw, err := json.Marshal(map[string]any{"host": target.Host, "probes": f.probes, "count": len(f.probes)})
		if err != nil {
			return nil, err
		}
		out[i] = sdk.Result{Capability: capability, RawJSON: raw, StartedAtUnixNano: 1, FinishedAtUnixNano: 2}
	}
	return out, nil
}

func decodeRaw(r sdk.Result) map[string]any {
	var m map[string]any
	Expect(json.Unmarshal(r.RawJSON, &m)).NotTo(HaveOccurred())
	return m
}

type callbackRunner struct{ run func() }

func (r *callbackRunner) RunEnumeration() { r.run() }
func (r *callbackRunner) Interrupt()      {}
func (r *callbackRunner) Close()          {}

func preserveEnv(name string) func() {
	value, ok := os.LookupEnv(name)
	return func() {
		if ok {
			_ = os.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	}
}

var _ = Describe("scanner", func() {
	It("configures asnmap from the VPT PDCP key", func() {
		previous := asnmap.PDCPApiKey
		DeferCleanup(func() { asnmap.PDCPApiKey = previous })

		_, err := newHTTPXProber(Options{PdcpAPIKey: "test-pdcp-key"})

		Expect(err).NotTo(HaveOccurred())
		Expect(asnmap.PDCPApiKey).To(Equal("test-pdcp-key"))
	})

	It("preserves the raw result shape", func() {
		fake := &fakeProber{probes: []ProbeResult{
			{URL: "https://example.com", Scheme: "https", StatusCode: 200, WebServer: "nginx"},
		}}
		s := newWithProber(fake, 0)

		var events []sdk.Event
		res, err := s.ExecuteStream(context.Background(), sdk.Target{Host: "example.com"}, func(e sdk.Event) error { events = append(events, e); return nil })
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Capability).To(Equal(capability))
		Expect(events).To(HaveLen(2))
		Expect(events[0].Type).To(Equal("scan_started"))
		Expect(events[1].Type).To(Equal("scan_completed"))
		raw := decodeRaw(res)
		Expect(raw["host"]).To(Equal("example.com"))
		Expect(raw["count"]).To(Equal(float64(1)))
		probes, _ := raw["probes"].([]any)
		Expect(probes).To(HaveLen(1))
		first, _ := probes[0].(map[string]any)
		Expect(first).To(HaveKeyWithValue("url", "https://example.com"))
		Expect(first).To(HaveKeyWithValue("web_server", "nginx"))
	})

	It("uses default and parameterized ports", func() {
		fake := &fakeProber{}
		s := newWithProber(fake, 0)
		_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.gotPorts).To(Equal("80,443"))

		fake2 := &fakeProber{}
		s2 := newWithProber(fake2, 0)
		_, err = s2.Execute(context.Background(), sdk.Target{Host: "  example.com  ", Params: map[string]string{"ports": "8080,8443"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(fake2.gotHost).To(Equal("example.com"))
		Expect(fake2.gotPorts).To(Equal("8080,8443"))
	})

	It("rejects an empty host without probing", func() {
		fake := &fakeProber{}
		s := newWithProber(fake, 0)
		_, err := s.Execute(context.Background(), sdk.Target{Host: "   "})
		Expect(err).To(MatchError("httpprobe: empty target host"))
		Expect(fake.calls).To(Equal(0))
	})

	It("returns prober errors", func() {
		boom := errors.New("dial timeout")
		fake := &fakeProber{err: boom}
		s := newWithProber(fake, 0)
		_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(MatchError(boom))
	})

	It("honors the per-call timeout", func() {
		fake := &fakeProber{block: true}
		s := newWithProber(fake, 20*time.Millisecond)
		start := time.Now()
		_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(HaveOccurred())
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
	})

	It("propagates caller cancellation to the prober", func() {
		fake := &fakeProber{block: true, started: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := newWithProber(fake, 0).Execute(ctx, sdk.Target{Host: "example.com"}); done <- err }()
		Eventually(fake.started).Should(BeClosed())
		cancel()
		Eventually(done).Should(Receive(MatchError(context.Canceled)))
	})

	It("reports its capability and has a no-op prepare", func() {
		s := &scanner{}
		c, err := s.Capability(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(c).To(Equal("httpprobe"))
		Expect(s.Prepare(context.Background(), "tok")).To(Succeed())
	})

	It("uses one native runner and preserves per-target result order", func() {
		oldFactory := newHTTPXRunner
		DeferCleanup(func() { newHTTPXRunner = oldFactory })
		calls := 0
		var got *runner.Options
		newHTTPXRunner = func(opts *runner.Options) (httpxRunner, error) {
			calls++
			got = opts
			return &callbackRunner{run: func() {
				opts.OnResult(runner.Result{Input: "b.example.com", URL: "https://b.example.com", Scheme: "https", StatusCode: 200})
				opts.OnResult(runner.Result{Input: "a.example.com", URL: "https://a.example.com/z", Scheme: "https", StatusCode: 200})
				opts.OnResult(runner.Result{Input: "a.example.com", URL: "https://a.example.com/a", Scheme: "https", StatusCode: 204})
			}}, nil
		}
		p, err := newHTTPXProber(Options{Threads: 25, Timeout: 45 * time.Second, MaxRunTime: time.Minute, Methods: []string{"POST"}})
		Expect(err).NotTo(HaveOccurred())
		params := map[string]string{"ports": "80,443", "request_timeout_seconds": "10", "follow_redirects": "true", "tech_detect": "true", "asn": "false"}
		targets := []sdk.Target{
			{Host: "a.example.com", Params: params, ContractID: "vpt/httpprobe/v1", ContractDigest: primaryManifestDigest()},
			{Host: "b.example.com", Params: params, ContractID: "vpt/httpprobe/v1", ContractDigest: primaryManifestDigest()},
			{Host: "empty.example.com", Params: params, ContractID: "vpt/httpprobe/v1", ContractDigest: primaryManifestDigest()},
		}
		results, err := p.ProbeBatch(context.Background(), targets)
		Expect(err).NotTo(HaveOccurred())
		Expect(calls).To(Equal(1))
		Expect([]string(got.InputTargetHost)).To(Equal([]string{"a.example.com", "b.example.com", "empty.example.com"}))
		Expect(got.Timeout).To(Equal(10))
		Expect(got.Methods).To(BeEmpty(), "primary contract must not inherit legacy methods")
		Expect(results).To(HaveLen(3))
		Expect(decodeRaw(results[0])["host"]).To(Equal("a.example.com"))
		probes := decodeRaw(results[0])["probes"].([]any)
		Expect(probes[0].(map[string]any)["url"]).To(Equal("https://a.example.com/a"))
		Expect(decodeRaw(results[1])["host"]).To(Equal("b.example.com"))
		Expect(decodeRaw(results[2])["count"]).To(Equal(float64(0)))
	})

	It("starts the max-run timeout only after the global gate is acquired", func() {
		oldFactory := newHTTPXRunner
		DeferCleanup(func() { newHTTPXRunner = oldFactory })
		newHTTPXRunner = func(*runner.Options) (httpxRunner, error) { return &callbackRunner{run: func() {}}, nil }
		<-httpxGlobalGate
		p, err := newHTTPXProber(Options{Threads: 1, Timeout: time.Second, MaxRunTime: 20 * time.Millisecond})
		Expect(err).NotTo(HaveOccurred())
		done := make(chan error, 1)
		go func() { _, callErr := p.Probe(context.Background(), "example.com", "80"); done <- callErr }()
		Consistently(done, 40*time.Millisecond).ShouldNot(Receive())
		httpxGlobalGate <- struct{}{}
		Eventually(done).Should(Receive(Succeed()))
	})

	It("keeps legacy semantic options and resets primary defaults", func() {
		base := Options{Timeout: 45 * time.Second, FollowRedirects: false, TechDetect: false, Methods: []string{"POST"}, ASN: true}
		legacy := executionOptions(base, map[string]string{"ports": "80,443"}, false)
		Expect(legacy).To(Equal(base))
		primary := executionOptions(base, map[string]string{"request_timeout_seconds": "7", "follow_redirects": "true", "tech_detect": "true", "asn": "false"}, true)
		Expect(primary.Timeout).To(Equal(7 * time.Second))
		Expect(primary.FollowRedirects).To(BeTrue())
		Expect(primary.TechDetect).To(BeTrue())
		Expect(primary.Methods).To(BeNil())
		Expect(primary.ASN).To(BeFalse())
	})

	It("applies runtime JSON over legacy environment and rejects invalid config", func() {
		for _, name := range []string{"VPT_NODE_HTTPPROBE_TIMEOUT", "VPT_NODE_HTTPPROBE_THREADS", "VPT_NODE_HTTPPROBE_MAX_RUN_TIME", "VPT_NODE_HTTPPROBE_FOLLOW_REDIRECTS", "VPT_NODE_HTTPPROBE_TECH_DETECT", "VPT_NODE_HTTPPROBE_METHODS", "VPT_NODE_HTTPPROBE_ASN", "VPT_NODE_PDCP_API_KEY", "VPT_PLUGIN_RUNTIME_CONFIG"} {
			DeferCleanup(preserveEnv(name))
			Expect(os.Unsetenv(name)).To(Succeed())
		}
		Expect(os.Setenv("VPT_NODE_HTTPPROBE_THREADS", "7")).To(Succeed())
		Expect(os.Setenv("VPT_NODE_HTTPPROBE_MAX_RUN_TIME", "1m")).To(Succeed())
		Expect(os.Setenv("VPT_NODE_HTTPPROBE_METHODS", "POST")).To(Succeed())
		Expect(os.Setenv("VPT_PLUGIN_RUNTIME_CONFIG", `{"threads":"31","max_run_time_seconds":"300"}`)).To(Succeed())
		opts, err := loadOptions()
		Expect(err).NotTo(HaveOccurred())
		Expect(opts.Threads).To(Equal(31))
		Expect(opts.MaxRunTime).To(Equal(5 * time.Minute))
		Expect(opts.Methods).To(Equal([]string{"POST"}))
		Expect(os.Setenv("VPT_PLUGIN_RUNTIME_CONFIG", `{"unknown":"1"}`)).To(Succeed())
		_, err = loadOptions()
		Expect(err).To(HaveOccurred())
	})
})
