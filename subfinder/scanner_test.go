package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trganda/vpt-scanner-plugins/sdk"
)

type fakeEnum struct {
	findings []Finding
	err      error
	calls    int
	gotHost  string
	block    bool
	write    func(io.Writer, io.Writer)
	started  chan struct{}
}

func (f *fakeEnum) Enumerate(ctx context.Context, domain string, stdout, stderr io.Writer) ([]Finding, error) {
	f.calls++
	f.gotHost = domain
	if f.block {
		if f.started != nil {
			close(f.started)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.write != nil {
		f.write(stdout, stderr)
	}
	return f.findings, f.err
}

var _ = Describe("scanner", func() {
	It("captures fragmented streams in order", func() {
		fake := &fakeEnum{write: func(stdout, stderr io.Writer) {
			_, _ = stdout.Write([]byte("out-"))
			_, _ = stderr.Write([]byte("err-"))
			_, _ = stdout.Write([]byte("one\nout-two\n"))
			_, _ = stderr.Write([]byte("one\nerr-two"))
		}}
		var events []sdk.Event
		_, err := newWithEnumerator(fake, 0).ExecuteStream(context.Background(), sdk.Target{Host: "example.com"}, func(e sdk.Event) error {
			events = append(events, e)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(events).To(HaveLen(6))
		want := []struct{ typ, level, line, stream string }{
			{"scan_started", "info", "", ""},
			{"log", "info", "out-one", "stdout"},
			{"log", "info", "out-two", "stdout"},
			{"log", "info", "err-one", "stderr"},
			{"log", "info", "err-two", "stderr"},
			{"scan_completed", "info", "", ""},
		}
		for i, expected := range want {
			Expect(events[i].Type).To(Equal(expected.typ))
			Expect(events[i].Level).To(Equal(expected.level))
			Expect(events[i].Fields["line"]).To(Equal(expected.line))
			Expect(events[i].Fields["stream"]).To(Equal(expected.stream))
			Expect(events[i].Sequence).To(Equal(int64(i + 1)))
		}
	})

	It("aggregates findings", func() {
		fake := &fakeEnum{findings: []Finding{
			{Host: "api.example.com", Source: "crtsh"},
			{Host: "www.example.com", Source: "crtsh"},
			{Host: "mail.example.com", Source: "hackertarget"},
		}}
		var events []sdk.Event
		res, err := newWithEnumerator(fake, 0).ExecuteStream(context.Background(), sdk.Target{Host: "example.com"}, func(e sdk.Event) error { events = append(events, e); return nil })
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Capability).To(Equal(capability))
		Expect(events).To(HaveLen(2))
		Expect(events[0].Type).To(Equal("scan_started"))
		Expect(events[1].Type).To(Equal("scan_completed"))
		raw := decodeRaw(res)
		Expect(raw["domain"]).To(Equal("example.com"))
		Expect(raw["count"]).To(Equal(float64(3)))
		subs, ok := raw["subdomains"].([]any)
		Expect(ok).To(BeTrue())
		Expect(subs).To(HaveLen(3))
		bySrc, ok := raw["by_source"].(map[string]any)
		Expect(ok).To(BeTrue())
		crtsh, ok := bySrc["crtsh"].([]any)
		Expect(ok).To(BeTrue())
		Expect(crtsh).To(HaveLen(2))
		Expect(fake.gotHost).To(Equal("example.com"))
	})

	It("trims the host", func() {
		fake := &fakeEnum{findings: []Finding{{Host: "a.example.com", Source: "crtsh"}}}
		_, err := newWithEnumerator(fake, 0).Execute(context.Background(), sdk.Target{Host: "  example.com  "})
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.gotHost).To(Equal("example.com"))
	})

	It("rejects an empty host", func() {
		fake := &fakeEnum{}
		_, err := newWithEnumerator(fake, 0).Execute(context.Background(), sdk.Target{Host: "   "})
		Expect(err).To(HaveOccurred())
		Expect(fake.calls).To(Equal(0))
	})

	It("returns enumerator errors", func() {
		boom := errors.New("source rate-limited")
		fake := &fakeEnum{err: boom}
		_, err := newWithEnumerator(fake, 0).Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(MatchError(boom))
	})

	It("honours the per-call timeout", func() {
		fake := &fakeEnum{block: true}
		start := time.Now()
		_, err := newWithEnumerator(fake, 20*time.Millisecond).Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(HaveOccurred())
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
	})

	It("propagates caller cancellation to the enumerator", func() {
		fake := &fakeEnum{block: true, started: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := newWithEnumerator(fake, 0).Execute(ctx, sdk.Target{Host: "example.com"})
			done <- err
		}()
		Eventually(fake.started).Should(BeClosed())
		cancel()
		Eventually(done).Should(Receive(MatchError(context.Canceled)))
	})

	It("surfaces initialization errors", func() {
		_, err := (&scanner{initErr: errors.New("bad provider config")}).Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(HaveOccurred())
	})

	It("reports its capability and prepares successfully", func() {
		s := &scanner{}
		c, err := s.Capability(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(c).To(Equal("subdomain"))
		Expect(s.Prepare(context.Background(), "tok")).To(Succeed())
	})
})

func decodeRaw(r sdk.Result) map[string]any {
	var m map[string]any
	Expect(json.Unmarshal(r.RawJSON, &m)).To(Succeed())
	return m
}
