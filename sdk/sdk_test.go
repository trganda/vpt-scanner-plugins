package sdk_test

import (
	"context"
	"encoding/json"
	"time"

	goplugin "github.com/hashicorp/go-plugin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trganda/vpt-scanner-plugins/sdk"
)

type stubScanner struct {
	gotTarget      sdk.Target
	gotToken       string
	startedExecute chan struct{}
	startedStream  chan struct{}
	blockExecute   bool
	blockStream    bool
}

func (s *stubScanner) Capability(context.Context) (string, error)    { return "portscan", nil }
func (s *stubScanner) Prepare(_ context.Context, token string) error { s.gotToken = token; return nil }
func (s *stubScanner) Execute(ctx context.Context, t sdk.Target) (sdk.Result, error) {
	s.gotTarget = t
	if s.startedExecute != nil {
		close(s.startedExecute)
	}
	if s.blockExecute {
		<-ctx.Done()
		return sdk.Result{}, ctx.Err()
	}
	raw, _ := json.Marshal(map[string]any{"host": t.Host, "echo": t.Params["k"]})
	return sdk.Result{Capability: "portscan", RawJSON: raw, StartedAtUnixNano: 1000, FinishedAtUnixNano: 2000}, nil
}
func (s *stubScanner) ExecuteStream(ctx context.Context, t sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	s.gotTarget = t
	if s.startedStream != nil {
		close(s.startedStream)
	}
	if s.blockStream {
		if sink != nil {
			if err := sink(sdk.Event{Sequence: 1, Type: "scan_started"}); err != nil {
				return sdk.Result{}, err
			}
		}
		<-ctx.Done()
		return sdk.Result{}, ctx.Err()
	}
	if sink != nil {
		if err := sink(sdk.Event{Sequence: 1, Level: "info", Type: "scan_started", Message: "started", OccurredAt: time.Unix(1, 0).UTC()}); err != nil {
			return sdk.Result{}, err
		}
	}
	raw, _ := json.Marshal(map[string]any{"host": t.Host, "echo": t.Params["k"]})
	return sdk.Result{Capability: "portscan", RawJSON: raw, StartedAtUnixNano: 1000, FinishedAtUnixNano: 2000}, nil
}

var _ = Describe("SDK", func() {
	It("keeps the handshake protocol version", func() {
		Expect(sdk.Handshake.ProtocolVersion).To(Equal(uint(1)), "want 1 for additive ExecuteStream rollout")
	})

	It("round-trips the gRPC protocol", func() {
		stub := &stubScanner{}
		client, _ := goplugin.TestPluginGRPCConn(GinkgoTB(), false, sdk.PluginMap(stub))
		DeferCleanup(func() { client.Close() })
		raw, err := client.Dispense(sdk.PluginName)
		Expect(err).NotTo(HaveOccurred())
		sc, ok := raw.(sdk.Scanner)
		Expect(ok).To(BeTrue(), "dispensed %T, want sdk.Scanner", raw)
		ctx := context.Background()
		cap, err := sc.Capability(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(cap).To(Equal("portscan"))
		res, err := sc.Execute(ctx, sdk.Target{Host: "example.com", Params: map[string]string{"k": "v"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(stub.gotTarget.Host).To(Equal("example.com"))
		Expect(stub.gotTarget.Params["k"]).To(Equal("v"))
		Expect(res.Capability).To(Equal("portscan"))
		Expect(res.StartedAtUnixNano).To(Equal(int64(1000)))
		Expect(res.FinishedAtUnixNano).To(Equal(int64(2000)))
		var decoded map[string]any
		Expect(json.Unmarshal(res.RawJSON, &decoded)).To(Succeed())
		Expect(decoded).To(HaveKeyWithValue("host", "example.com"))
		Expect(decoded).To(HaveKeyWithValue("echo", "v"))
		var events []sdk.Event
		res, err = sc.ExecuteStream(ctx, sdk.Target{Host: "example.com"}, func(event sdk.Event) error { events = append(events, event); return nil })
		Expect(err).NotTo(HaveOccurred())
		Expect(events).To(HaveLen(1))
		Expect(events[0].Type).To(Equal("scan_started"))
		Expect(res.Capability).To(Equal("portscan"))
		Expect(sc.Prepare(ctx, "tok-123")).To(Succeed())
		Expect(stub.gotToken).To(Equal("tok-123"))
	})

	It("propagates unary cancellation to the plugin and returns without a result", func() {
		stub := &stubScanner{startedExecute: make(chan struct{}), blockExecute: true}
		conn, _ := goplugin.TestPluginGRPCConn(GinkgoTB(), false, sdk.PluginMap(stub))
		DeferCleanup(func() { conn.Close() })
		raw, err := conn.Dispense(sdk.PluginName)
		Expect(err).NotTo(HaveOccurred())
		sc := raw.(sdk.Scanner)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var result sdk.Result
		var callErr error
		go func() { result, callErr = sc.Execute(ctx, sdk.Target{Host: "example.com"}); close(done) }()
		Eventually(stub.startedExecute).Should(BeClosed())
		cancel()
		Eventually(done).Should(BeClosed())
		Expect(callErr).To(HaveOccurred())
		Expect(result).To(Equal(sdk.Result{}))
	})

	It("propagates streaming cancellation and suppresses the terminal result", func() {
		stub := &stubScanner{startedStream: make(chan struct{}), blockStream: true}
		conn, _ := goplugin.TestPluginGRPCConn(GinkgoTB(), false, sdk.PluginMap(stub))
		DeferCleanup(func() { conn.Close() })
		raw, err := conn.Dispense(sdk.PluginName)
		Expect(err).NotTo(HaveOccurred())
		sc := raw.(sdk.Scanner)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var result sdk.Result
		var callErr error
		go func() { result, callErr = sc.ExecuteStream(ctx, sdk.Target{Host: "example.com"}, nil); close(done) }()
		Eventually(stub.startedStream).Should(BeClosed())
		cancel()
		Eventually(done).Should(BeClosed())
		Expect(callErr).To(HaveOccurred())
		Expect(result).To(Equal(sdk.Result{}))
	})

	It("lets a cancelled blocked sink stop streaming promptly", func() {
		stub := &stubScanner{startedStream: make(chan struct{}), blockStream: true}
		conn, _ := goplugin.TestPluginGRPCConn(GinkgoTB(), false, sdk.PluginMap(stub))
		DeferCleanup(func() { conn.Close() })
		raw, err := conn.Dispense(sdk.PluginName)
		Expect(err).NotTo(HaveOccurred())
		sc := raw.(sdk.Scanner)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_, _ = sc.ExecuteStream(ctx, sdk.Target{Host: "example.com"}, func(sdk.Event) error { <-ctx.Done(); return ctx.Err() })
			close(done)
		}()
		Eventually(stub.startedStream).Should(BeClosed())
		cancel()
		Eventually(done).Should(BeClosed())
	})
})
