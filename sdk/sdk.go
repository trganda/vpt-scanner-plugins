// Package sdk is the shared contract between the scanner host and tool plugins.
// It holds the go-plugin handshake, the gRPC client/server bridge to the
// scan.v1 proto, and plain DTOs so neither side needs the other's domain types.
//
// A plugin author implements Scanner and calls Serve from main(). The host
// dispenses a Scanner (backed by GRPCClient) and adapts it to its own
// scan.Executor port. The host's domain types (scan.Target/ScanResult) and the
// plugin's tool dependencies never cross this boundary.
package sdk

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	scanv1 "github.com/trganda/vpt-scanner-plugins/sdk/proto/scan/v1"
)

// PluginName is the key under which the single scanner plugin is dispensed.
const PluginName = "scanner"

// Handshake is shared by host and plugin. The magic cookie is a UX guard (so a
// plugin binary run directly prints a friendly message), not a security
// boundary. ProtocolVersion is bumped only on a breaking contract change.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "VPT_SCAN_PLUGIN",
	MagicCookieValue: "vpt-scanner-plugin",
}

// Target is the host→plugin scan input, mirroring scan.Target.
type Target struct {
	Host   string
	Params map[string]string
}

// Result is the plugin→host scan output. RawJSON is json.Marshal of the tool's
// ScanResult.Raw map; the host unmarshals it back into map[string]any.
type Result struct {
	Capability         string
	RawJSON            []byte
	StartedAtUnixNano  int64
	FinishedAtUnixNano int64
}

// Scanner is the interface a plugin implements and the host consumes. It is the
// gRPC-friendly mirror of the host's scan.Executor port.
type Scanner interface {
	// Capability returns the tool's capability string (e.g. "portscan").
	Capability(ctx context.Context) (string, error)
	// Execute runs one scan against t and returns the tool-specific result.
	Execute(ctx context.Context, t Target) (Result, error)
	// Prepare is a pre-scan hook. Every tool except nuclei returns nil; nuclei
	// uses authToken to sync its template bundle before scans run.
	Prepare(ctx context.Context, authToken string) error
}

// ScannerPlugin adapts a Scanner implementation to go-plugin's GRPCPlugin.
type ScannerPlugin struct {
	plugin.Plugin
	Impl Scanner
}

func (p *ScannerPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	scanv1.RegisterScanPluginServer(s, &gRPCServer{impl: p.Impl})
	return nil
}

func (p *ScannerPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &GRPCClient{client: scanv1.NewScanPluginClient(c)}, nil
}

// PluginMap is the dispense map served by a plugin / consumed by the host.
func PluginMap(impl Scanner) map[string]plugin.Plugin {
	return map[string]plugin.Plugin{PluginName: &ScannerPlugin{Impl: impl}}
}

// Serve is the plugin entrypoint: a tool's main() builds its Scanner and calls
// this. It blocks until the host disconnects. Tool logging must go to stderr —
// go-plugin uses stdout for the handshake.
func Serve(impl Scanner) {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         PluginMap(impl),
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}

// GRPCClient is the host-side Scanner that talks to the plugin over gRPC.
type GRPCClient struct {
	client scanv1.ScanPluginClient
}

var _ Scanner = (*GRPCClient)(nil)

func (m *GRPCClient) Capability(ctx context.Context) (string, error) {
	resp, err := m.client.Capability(ctx, &scanv1.CapabilityRequest{})
	if err != nil {
		return "", err
	}
	return resp.GetCapability(), nil
}

func (m *GRPCClient) Execute(ctx context.Context, t Target) (Result, error) {
	resp, err := m.client.Execute(ctx, &scanv1.ExecuteRequest{
		Host:   t.Host,
		Params: t.Params,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{
		Capability:         resp.GetCapability(),
		RawJSON:            resp.GetRawJson(),
		StartedAtUnixNano:  resp.GetStartedAtUnixNano(),
		FinishedAtUnixNano: resp.GetFinishedAtUnixNano(),
	}, nil
}

func (m *GRPCClient) Prepare(ctx context.Context, authToken string) error {
	_, err := m.client.Prepare(ctx, &scanv1.PrepareRequest{AuthToken: authToken})
	return err
}

// gRPCServer is the plugin-side bridge from the proto service to the Scanner.
type gRPCServer struct {
	scanv1.UnimplementedScanPluginServer
	impl Scanner
}

func (m *gRPCServer) Capability(ctx context.Context, _ *scanv1.CapabilityRequest) (*scanv1.CapabilityResponse, error) {
	c, err := m.impl.Capability(ctx)
	if err != nil {
		return nil, err
	}
	return &scanv1.CapabilityResponse{Capability: c}, nil
}

func (m *gRPCServer) Execute(ctx context.Context, req *scanv1.ExecuteRequest) (*scanv1.ExecuteResponse, error) {
	res, err := m.impl.Execute(ctx, Target{Host: req.GetHost(), Params: req.GetParams()})
	if err != nil {
		return nil, err
	}
	return &scanv1.ExecuteResponse{
		Capability:         res.Capability,
		RawJson:            res.RawJSON,
		StartedAtUnixNano:  res.StartedAtUnixNano,
		FinishedAtUnixNano: res.FinishedAtUnixNano,
	}, nil
}

func (m *gRPCServer) Prepare(ctx context.Context, req *scanv1.PrepareRequest) (*scanv1.PrepareResponse, error) {
	if err := m.impl.Prepare(ctx, req.GetAuthToken()); err != nil {
		return nil, err
	}
	return &scanv1.PrepareResponse{}, nil
}
