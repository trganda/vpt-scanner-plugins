package sdk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	goplugin "github.com/hashicorp/go-plugin"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trganda/vpt-scanner-plugins/sdk"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func strptr(s string) *string { return &s }

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
	It("exposes a stable, copied capability list", func() {
		capabilities := sdk.Capabilities()
		Expect(capabilities).To(Equal([]string{"subdomain", "portscan", "httpprobe", "vuln", "katana", "cloudlist"}))
		capabilities[0] = "changed"
		Expect(sdk.Capabilities()[0]).To(Equal("subdomain"))
		Expect(sdk.SupportsCapability("cloudlist")).To(BeTrue())
		Expect(sdk.SupportsCapability("unknown")).To(BeFalse())
	})

	It("round-trips manifest description and canonical contract execution", func() {
		manifest := contract.Manifest{ManifestVersion: 1, Capability: "portscan", ContractID: "vpt/portscan/v1", Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{"host/v1"}, Cardinality: "one"}}, Outputs: []contract.Output{{Name: "host", Type: "host/v1", Cardinality: "one"}}, Parameters: []contract.Parameter{{Name: "mode", Kind: "enum", Enum: []string{"fast", "full"}, Default: strptr("fast")}}}
		d, err := contract.Compile(manifest)
		Expect(err).NotTo(HaveOccurred())
		var printed bytes.Buffer
		handled, err := sdk.PrintManifestIfRequested(manifest, []string{"--print-manifest"}, &printed)
		Expect(err).NotTo(HaveOccurred())
		Expect(handled).To(BeTrue())
		Expect(printed.Bytes()).To(Equal(d.CanonicalJSON()))
		Expect(printed.String()).NotTo(HaveSuffix("\n"))
		handled, err = sdk.PrintManifestIfRequested(manifest, []string{"serve"}, &printed)
		Expect(err).NotTo(HaveOccurred())
		Expect(handled).To(BeFalse())
		stub := &stubScanner{}
		calls := 0
		pm, err := sdk.PluginMapWithManifest(stub, manifest, sdk.ManifestOptions{
			TargetMapper: func(target sdk.Target) (sdk.Target, error) {
				target.Params["mapped"] = "true"
				return target, nil
			},
			OutputMapper: func(t sdk.Target, _ sdk.Result) ([]contract.NamedOutput, error) {
				calls++
				v, e := contract.Host(t.Host)
				return []contract.NamedOutput{{Name: "host", Values: []contract.Value{v}}}, e
			},
		})
		Expect(err).NotTo(HaveOccurred())
		conn, _ := goplugin.TestPluginGRPCConn(GinkgoTB(), false, pm)
		DeferCleanup(func() { conn.Close() })
		raw, err := conn.Dispense(sdk.PluginName)
		Expect(err).NotTo(HaveOccurred())
		desc := raw.(sdk.Describer)
		ce := raw.(sdk.ContractExecutor)
		got, err := desc.Describe(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(got.CanonicalManifestJSON).To(Equal(d.CanonicalJSON()))
		Expect(got.Capability).To(Equal(manifest.Capability))
		Expect(got.ContractID).To(Equal(manifest.ContractID))
		Expect(got.ContractDigest).To(Equal(d.Digest()))
		Expect(got.ManifestSHA256).To(Equal(d.ManifestDigest()))
		Expect(got.ProtocolVersion).To(Equal(uint32(1)))
		res, err := ce.ExecuteContract(context.Background(), sdk.ContractRequest{Target: sdk.Target{Host: "EXAMPLE.COM"}, ContractID: manifest.ContractID, ContractDigest: d.Digest()})
		Expect(err).NotTo(HaveOccurred())
		Expect(stub.gotTarget.Host).To(Equal("example.com"))
		Expect(stub.gotTarget.Params).To(Equal(map[string]string{"mode": "fast", "mapped": "true"}))
		Expect(res.Result.Capability).To(Equal("portscan"))
		Expect(res.Result.StartedAtUnixNano).To(Equal(int64(1000)))
		Expect(res.Result.FinishedAtUnixNano).To(Equal(int64(2000)))
		Expect(res.ContractID).To(Equal(manifest.ContractID))
		Expect(res.ContractDigest).To(Equal(d.Digest()))
		Expect(res.Outputs[0].Values[0].String()).To(Equal("example.com"))
		Expect(calls).To(Equal(1))
		var events []sdk.Event
		streamed, err := ce.ExecuteStreamContract(context.Background(), sdk.ContractRequest{Target: sdk.Target{Host: "EXAMPLE.COM"}, ContractID: manifest.ContractID, ContractDigest: d.Digest()}, func(event sdk.Event) error {
			events = append(events, event)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(events).To(HaveLen(1))
		Expect(streamed).To(Equal(res))
		Expect(calls).To(Equal(2))

		legacy := raw.(sdk.Scanner)
		_, err = legacy.Execute(context.Background(), sdk.Target{Host: "legacy target", Params: map[string]string{"unknown": "preserved"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(stub.gotTarget).To(Equal(sdk.Target{Host: "legacy target", Params: map[string]string{"unknown": "preserved"}}))
		_, err = legacy.ExecuteStream(context.Background(), sdk.Target{Host: "legacy stream", Params: map[string]string{"unknown": "preserved"}}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(calls).To(Equal(2), "legacy requests must not invoke the output mapper")

		_, err = ce.ExecuteContract(context.Background(), sdk.ContractRequest{ContractID: manifest.ContractID})
		Expect(status.Code(err)).To(Equal(codes.InvalidArgument))
		_, err = ce.ExecuteContract(context.Background(), sdk.ContractRequest{})
		Expect(status.Code(err)).To(Equal(codes.FailedPrecondition))
		_, err = ce.ExecuteContract(context.Background(), sdk.ContractRequest{Target: sdk.Target{Host: "example.com"}, ContractID: manifest.ContractID, ContractDigest: "sha256:" + string(bytes.Repeat([]byte("0"), 64))})
		Expect(status.Code(err)).To(Equal(codes.FailedPrecondition))
	})

	It("keeps manifest-free plugins legacy-only and validates serving constraints", func() {
		stub := &stubScanner{}
		conn, _ := goplugin.TestPluginGRPCConn(GinkgoTB(), false, sdk.PluginMap(stub))
		DeferCleanup(func() { conn.Close() })
		raw, err := conn.Dispense(sdk.PluginName)
		Expect(err).NotTo(HaveOccurred())
		_, err = raw.(sdk.Describer).Describe(context.Background())
		Expect(status.Code(err)).To(Equal(codes.Unimplemented))
		_, err = raw.(sdk.ContractExecutor).ExecuteContract(context.Background(), sdk.ContractRequest{Target: sdk.Target{Host: "example.com"}, ContractID: "vpt/portscan/v1", ContractDigest: "sha256:" + string(bytes.Repeat([]byte("0"), 64))})
		Expect(status.Code(err)).To(Equal(codes.FailedPrecondition))

		manifest := contract.Manifest{ManifestVersion: 1, Capability: "portscan", ContractID: "vpt/portscan/v1", Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{"host/v1"}, Cardinality: "many"}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{}}
		_, err = sdk.PluginMapWithManifest(stub, manifest, sdk.ManifestOptions{})
		Expect(err).To(HaveOccurred())
		manifest.Inputs[0].Cardinality = "one"
		manifest.Outputs = []contract.Output{{Name: "hosts", Type: "host/v1", Cardinality: "many"}}
		_, err = sdk.PluginMapWithManifest(stub, manifest, sdk.ManifestOptions{})
		Expect(err).To(MatchError(ContainSubstring("output mapper")))
	})
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
