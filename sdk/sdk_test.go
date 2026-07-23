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
	gotTarget sdk.Target
	gotToken  string
}

func (s *stubScanner) Capability(context.Context) (string, error)    { return "portscan", nil }
func (s *stubScanner) Prepare(_ context.Context, token string) error { s.gotToken = token; return nil }
func (s *stubScanner) Execute(_ context.Context, t sdk.Target) (sdk.Result, error) {
	return s.ExecuteStream(context.Background(), t, nil)
}
func (s *stubScanner) ExecuteStream(_ context.Context, t sdk.Target, sink sdk.EventSink) (sdk.Result, error) {
	s.gotTarget = t
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
})
