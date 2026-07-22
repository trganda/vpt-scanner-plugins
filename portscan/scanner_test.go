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

// fakeScanner is a double for the package-private portScanner port so these
// tests don't pull naabu or live network in.
type fakeScanner struct {
	ports    []PortResult
	err      error
	calls    int
	gotHost  string
	gotPorts string
	block    bool
}

func (f *fakeScanner) Scan(ctx context.Context, host, ports string) ([]PortResult, error) {
	f.calls++
	f.gotHost = host
	f.gotPorts = ports
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.ports, f.err
}

func decodeRaw(r sdk.Result) map[string]any {
	var m map[string]any
	Expect(json.Unmarshal(r.RawJSON, &m)).To(Succeed())
	return m
}

var _ = Describe("portscan scanner", func() {
	It("returns the expected raw result shape", func() {
		fake := &fakeScanner{ports: []PortResult{{Port: 80, Protocol: "tcp"}, {Port: 443, Protocol: "tcp"}}}
		s := newWithScanner(fake, 0)

		var events []sdk.Event
		res, err := s.ExecuteStream(context.Background(), sdk.Target{Host: "example.com"}, func(e sdk.Event) error { events = append(events, e); return nil })
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Capability).To(Equal(capability))
		Expect(events).To(HaveLen(2))
		Expect(events[0].Type).To(Equal("scan_started"))
		Expect(events[1].Type).To(Equal("scan_completed"))
		raw := decodeRaw(res)
		Expect(raw["host"]).To(Equal("example.com"))
		Expect(raw["count"]).To(Equal(float64(2)))
		Expect(fake.gotHost).To(Equal("example.com"))
		Expect(fake.gotPorts).To(Equal("100"))
	})

	It("passes and trims the ports parameter", func() {
		fake := &fakeScanner{}
		s := newWithScanner(fake, 0)

		_, err := s.Execute(context.Background(), sdk.Target{
			Host:   "  example.com  ",
			Params: map[string]string{"ports": "22,80,443"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.gotHost).To(Equal("example.com"))
		Expect(fake.gotPorts).To(Equal("22,80,443"))
	})

	It("rejects an empty host without scanning", func() {
		fake := &fakeScanner{}
		s := newWithScanner(fake, 0)

		_, err := s.Execute(context.Background(), sdk.Target{Host: "   "})
		Expect(err).To(HaveOccurred())
		Expect(fake.calls).To(Equal(0))
	})

	It("returns scanner errors", func() {
		boom := errors.New("connection refused")
		fake := &fakeScanner{err: boom}
		s := newWithScanner(fake, 0)

		_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(errors.Is(err, boom)).To(BeTrue())
	})

	It("honors the per-call timeout", func() {
		fake := &fakeScanner{block: true}
		s := newWithScanner(fake, 20*time.Millisecond)

		start := time.Now()
		_, err := s.Execute(context.Background(), sdk.Target{Host: "example.com"})
		Expect(err).To(HaveOccurred())
		Expect(time.Since(start)).To(BeNumerically("<", time.Second))
	})

	It("reports its capability and prepares successfully", func() {
		s := newScanner()
		c, err := s.Capability(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(c).To(Equal("portscan"))
		Expect(s.Prepare(context.Background(), "tok")).To(Succeed())
	})
})
