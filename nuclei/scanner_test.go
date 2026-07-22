package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trganda/vpt-scanner-plugins/sdk"
)

type fakeEngine struct {
	findings []Finding
	err      error
	gotHost  string
}

func (f *fakeEngine) Scan(_ context.Context, target string, _ map[string]string) ([]Finding, error) {
	f.gotHost = target
	return f.findings, f.err
}

var _ = Describe("scanner", func() {
	It("returns the raw scan shape and emits events", func() {
		fake := &fakeEngine{findings: []Finding{{TemplateID: "cve-2021-1234", Severity: "high", Host: "https://t", CVEIDs: []string{"CVE-2021-1234"}}}}
		s := newWithEngine(fake)
		var events []sdk.Event
		res, err := s.ExecuteStream(context.Background(), sdk.Target{Host: "https://t"}, func(e sdk.Event) error { events = append(events, e); return nil })
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Capability).To(Equal(capability))
		Expect(events).To(HaveLen(2))
		Expect(events[0].Type).To(Equal("scan_started"))
		Expect(events[1].Type).To(Equal("scan_completed"))
		var raw map[string]any
		Expect(json.Unmarshal(res.RawJSON, &raw)).To(Succeed())
		Expect(raw["host"]).To(Equal("https://t"))
		Expect(raw["count"]).To(Equal(float64(1)))
		Expect(fake.gotHost).To(Equal("https://t"))
	})

	It("returns engine errors", func() {
		boom := errors.New("nuclei exploded")
		_, err := newWithEngine(&fakeEngine{err: boom}).Execute(context.Background(), sdk.Target{Host: "https://t"})
		Expect(errors.Is(err, boom)).To(BeTrue())
	})

	It("surfaces initialization errors from Execute and Prepare", func() {
		s := &scanner{initErr: errors.New("template dir required")}
		_, err := s.Execute(context.Background(), sdk.Target{Host: "https://t"})
		Expect(err).To(HaveOccurred())
		Expect(s.Prepare(context.Background(), "tok")).To(HaveOccurred())
	})

	It("reports the vulnerability capability", func() {
		c, err := (&scanner{}).Capability(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(c).To(Equal("vuln"))
	})

	Describe("fetchBundle", func() {
		It("sets the authorization header from the node JWT", func() {
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
			}))
			DeferCleanup(srv.Close)
			_, err := (&syncer{bundleURL: srv.URL, httpClient: srv.Client()}).fetchBundle(context.Background(), "template", "node-jwt")
			Expect(err).NotTo(HaveOccurred())
			Expect(gotAuth).To(Equal("Bearer node-jwt"))
		})

		It("omits authorization when there is no token", func() {
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
			}))
			DeferCleanup(srv.Close)
			_, err := (&syncer{bundleURL: srv.URL, httpClient: srv.Client()}).fetchBundle(context.Background(), "template", "")
			Expect(err).NotTo(HaveOccurred())
			Expect(gotAuth).To(BeEmpty())
		})

		It("errors on an unauthorized response", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
			DeferCleanup(srv.Close)
			_, err := (&syncer{bundleURL: srv.URL, httpClient: srv.Client()}).fetchBundle(context.Background(), "template", "x")
			Expect(err).To(HaveOccurred())
		})

		It("returns the envelope data", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"success":true,"data":[{"id":"tmpl-1","presigned_url":"https://s3/tmpl-1"}]}`)) }))
			DeferCleanup(srv.Close)
			entries, err := (&syncer{bundleURL: srv.URL, httpClient: srv.Client()}).fetchBundle(context.Background(), "template", "x")
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].ID).To(Equal("tmpl-1"))
		})

		It("errors on an unsuccessful envelope", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"success":false,"error":{"code":"internal","message":"boom"}}`)) }))
			DeferCleanup(srv.Close)
			_, err := (&syncer{bundleURL: srv.URL, httpClient: srv.Client()}).fetchBundle(context.Background(), "template", "x")
			Expect(err).To(HaveOccurred())
		})
	})
})
