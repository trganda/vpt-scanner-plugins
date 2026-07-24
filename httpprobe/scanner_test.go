package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

func (f *fakeProber) Probe(ctx context.Context, host, ports string) ([]ProbeResult, error) {
	f.calls++
	f.gotHost = host
	f.gotPorts = ports
	if f.block {
		if f.started != nil {
			close(f.started)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.probes, f.err
}

func decodeRaw(r sdk.Result) map[string]any {
	var m map[string]any
	Expect(json.Unmarshal(r.RawJSON, &m)).NotTo(HaveOccurred())
	return m
}

var _ = Describe("scanner", func() {
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

	It("surfaces initialization errors", func() {
		s := &scanner{initErr: errors.New("bad options")}
		_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(MatchError("bad options"))
	})

	It("reports its capability and has a no-op prepare", func() {
		s := &scanner{}
		c, err := s.Capability(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(c).To(Equal("httpprobe"))
		Expect(s.Prepare(context.Background(), "tok")).To(Succeed())
	})
})
