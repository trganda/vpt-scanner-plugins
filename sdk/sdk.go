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
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/go-plugin"
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	scanv1 "github.com/trganda/vpt-scanner-plugins/sdk/proto/scan/v1"
)

// ContractProtocolVersion is the additive SDK protocol reported by Describe.
const ContractProtocolVersion = contract.ProtocolVersion

// Version is the released semantic version of this SDK source.
const Version = "v0.6.0"

var (
	buildPluginVersion string
	buildSourceCommit  string
)

// ReleaseBuildMetadata returns compile-time release identity while preserving a
// zero value for local builds. Release automation sets the private string vars
// with -ldflags -X; a partially configured release fails ManifestOptions
// validation rather than serving ambiguous identity.
func ReleaseBuildMetadata(features []string, runtimeRequirements map[string]string) BuildMetadata {
	if buildPluginVersion == "" && buildSourceCommit == "" {
		return BuildMetadata{}
	}
	return BuildMetadata{PluginVersion: buildPluginVersion, SDKVersion: Version, SourceCommit: buildSourceCommit, Features: append([]string(nil), features...), RuntimeRequirements: cloneStrings(runtimeRequirements)}
}

// Capabilities returns all capabilities supported by this SDK in stable order.
// The returned slice is a copy and may be safely changed by the caller.
func Capabilities() []string {
	known := contract.Capabilities()
	out := make([]string, len(known))
	for i, capability := range known {
		out[i] = string(capability)
	}
	return out
}

// SupportsCapability reports whether value is a capability supported by this SDK.
func SupportsCapability(value string) bool { return contract.IsCapability(value) }

// CapabilityMetadata is immutable source metadata for one SDK capability.
type CapabilityMetadata struct {
	Capability string
	Module     string
}

// LookupCapability returns immutable metadata for a supported capability.
func LookupCapability(value string) (CapabilityMetadata, bool) {
	metadata, ok := contract.LookupCapability(value)
	if !ok {
		return CapabilityMetadata{}, false
	}
	return CapabilityMetadata{Capability: string(metadata.Capability), Module: metadata.Module}, true
}

// PluginName is the key under which the single scanner plugin is dispensed.
const PluginName = "scanner"

// Handshake is shared by host and plugin. The magic cookie is a UX guard (so a
// plugin binary run directly prints a friendly message), not a security
// boundary. ProtocolVersion is bumped only on a breaking contract change.
var Handshake = plugin.HandshakeConfig{
	// ExecuteStream is an additive gRPC method, so retain handshake version 1
	// for rolling compatibility with hosts and plugins using Execute.
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

// ContractRequest pins a scan target to one semantic capability contract.
type ContractRequest struct {
	Target         Target
	ContractID     string
	ContractDigest string
}

// ContractResult combines the unchanged raw result with orchestration outputs.
type ContractResult struct {
	Result         Result
	Outputs        []contract.NamedOutput
	ContractID     string
	ContractDigest string
}

// ContractExecutor is the optional contract-bearing execution API implemented by GRPCClient.
type ContractExecutor interface {
	ExecuteContract(context.Context, ContractRequest) (ContractResult, error)
	ExecuteStreamContract(context.Context, ContractRequest, EventSink) (ContractResult, error)
}

// Description reports the immutable manifest served by a plugin binary.
type Description struct {
	Capability            string
	CanonicalManifestJSON []byte
	ContractID            string
	ContractDigest        string
	ManifestSHA256        string
	ProtocolVersion       uint32
	PluginVersion         string
	SDKVersion            string
	SourceCommit          string
	Features              []string
	RuntimeRequirements   map[string]string
}

// Describer is the optional manifest discovery API implemented by GRPCClient.
type Describer interface {
	Describe(context.Context) (Description, error)
}

// CheckStatus is the bounded health state returned by an optional Checker.
type CheckStatus string

const (
	CheckStatusOK        CheckStatus = "ok"
	CheckStatusDegraded  CheckStatus = "degraded"
	CheckStatusUnhealthy CheckStatus = "unhealthy"
)

// CheckIssue is safe, bounded health information. It must not contain tool
// output, credentials, request parameters, or request/response bodies.
type CheckIssue struct {
	Code    string
	Message string
}

// CheckResult is the result of an optional, side-effect-free plugin check.
type CheckResult struct {
	Status CheckStatus
	Issues []CheckIssue
}

// Checker is an optional plugin health interface. GRPCClient implements it;
// plugins that do not implement it return codes.Unimplemented.
type Checker interface {
	Check(context.Context) (CheckResult, error)
}

// ExecutionError is a safe, machine-readable scan failure. Details must be
// small non-sensitive values suitable for orchestration decisions.
type ExecutionError struct {
	Code      string
	Message   string
	Retryable bool
	Details   map[string]string
	status    *status.Status
}

// NewExecutionError constructs a typed execution failure and copies details.
func NewExecutionError(code, message string, retryable bool, details map[string]string) *ExecutionError {
	return &ExecutionError{Code: code, Message: message, Retryable: retryable, Details: cloneStrings(details)}
}

func (e *ExecutionError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

// GRPCStatus preserves the original gRPC status after client-side decoding.
func (e *ExecutionError) GRPCStatus() *status.Status {
	if e.status != nil {
		return e.status
	}
	return status.New(codes.Unknown, e.Error())
}

// AsExecutionError extracts a typed execution failure and returns a safe copy.
func AsExecutionError(err error) (*ExecutionError, bool) {
	var executionError *ExecutionError
	if !errors.As(err, &executionError) || executionError == nil {
		return nil, false
	}
	out := *executionError
	out.Details = cloneStrings(executionError.Details)
	return &out, true
}

// Event is a safe, structured progress update. Sequence is local to one
// ExecuteStream call. Fields are intentionally string-valued and bounded by
// the bridge; implementations must not put credentials, parameters, bodies,
// or tool output in an event. Log events use Fields["line"] for lossless raw
// output and Fields["stream"] with values stdout or stderr.
type Event struct {
	Sequence   int64
	Level      string
	Type       string
	Message    string
	Fields     map[string]string
	OccurredAt time.Time
}

// EventSink receives progress events. Returning an error stops delivery and
// causes the scan to fail without exposing tool output.
type EventSink func(Event) error

// NewEvent constructs a progress event with the current UTC timestamp.
func NewEvent(level, typ, message string, fields map[string]string) Event {
	return Event{Level: level, Type: typ, Message: message, Fields: fields, OccurredAt: time.Now().UTC()}
}

// Scanner is the interface a plugin implements and the host consumes. It is the
// gRPC-friendly mirror of the host's scan.Executor port.
type Scanner interface {
	// Capability returns the tool's capability string (e.g. "portscan").
	Capability(ctx context.Context) (string, error)
	// Execute runs one scan against t and returns the tool-specific result.
	Execute(ctx context.Context, t Target) (Result, error)
	ExecuteStream(ctx context.Context, t Target, sink EventSink) (Result, error)
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

// ManifestOptions configures plugin-owned typed output conversion.
type ManifestOptions struct {
	TargetMapper  func(Target) (Target, error)
	OutputMapper  func(Target, Result) ([]contract.NamedOutput, error)
	BuildMetadata BuildMetadata
}

// BuildMetadata is immutable release identity embedded by a plugin build. The
// zero value preserves compatibility with plugins that predate build metadata.
type BuildMetadata struct {
	PluginVersion       string
	SDKVersion          string
	SourceCommit        string
	Features            []string
	RuntimeRequirements map[string]string
}

type manifestScannerPlugin struct {
	plugin.Plugin
	impl       Scanner
	descriptor *contract.Descriptor
	options    ManifestOptions
}

func (p *manifestScannerPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	scanv1.RegisterScanPluginServer(s, &gRPCServer{impl: p.impl, contract: p.descriptor, options: p.options})
	return nil
}

func (p *manifestScannerPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &GRPCClient{client: scanv1.NewScanPluginClient(c)}, nil
}

// PluginMapWithManifest validates and serves a scanner with a manifest contract.
func PluginMapWithManifest(impl Scanner, manifest contract.Manifest, opts ManifestOptions) (map[string]plugin.Plugin, error) {
	d, e := contract.Compile(manifest)
	if e != nil {
		return nil, e
	}
	m := d.Manifest()
	if len(m.Inputs) != 1 || m.Inputs[0].Name != "target" || m.Inputs[0].Cardinality != string(contract.CardinalityOne) {
		return nil, fmt.Errorf("manifest must declare exactly one target input")
	}
	if len(d.Manifest().Outputs) > 0 && opts.OutputMapper == nil {
		return nil, fmt.Errorf("output mapper is required")
	}
	if err := validateBuildMetadata(opts.BuildMetadata); err != nil {
		return nil, err
	}
	opts.BuildMetadata.Features = append([]string(nil), opts.BuildMetadata.Features...)
	opts.BuildMetadata.RuntimeRequirements = cloneStrings(opts.BuildMetadata.RuntimeRequirements)
	return map[string]plugin.Plugin{PluginName: &manifestScannerPlugin{impl: impl, descriptor: d, options: opts}}, nil
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

// ServeWithManifest starts a scanner plugin with its validated manifest.
func ServeWithManifest(impl Scanner, manifest contract.Manifest, opts ManifestOptions) error {
	p, e := PluginMapWithManifest(impl, manifest, opts)
	if e != nil {
		return e
	}
	plugin.Serve(&plugin.ServeConfig{HandshakeConfig: Handshake, Plugins: p, GRPCServer: plugin.DefaultGRPCServer})
	return nil
}

// PrintManifestIfRequested prints canonical manifest bytes for the standalone flag.
func PrintManifestIfRequested(manifest contract.Manifest, args []string, stdout io.Writer) (bool, error) {
	if len(args) != 1 || args[0] != "--print-manifest" {
		return false, nil
	}
	d, e := contract.Compile(manifest)
	if e != nil {
		return true, e
	}
	_, e = stdout.Write(d.CanonicalJSON())
	return true, e
}

// GRPCClient is the host-side Scanner that talks to the plugin over gRPC.
type GRPCClient struct {
	client scanv1.ScanPluginClient
}

var _ Scanner = (*GRPCClient)(nil)
var _ ContractExecutor = (*GRPCClient)(nil)
var _ Describer = (*GRPCClient)(nil)
var _ Checker = (*GRPCClient)(nil)

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
		return Result{}, decodeExecutionError(err)
	}
	return Result{
		Capability:         resp.GetCapability(),
		RawJSON:            resp.GetRawJson(),
		StartedAtUnixNano:  resp.GetStartedAtUnixNano(),
		FinishedAtUnixNano: resp.GetFinishedAtUnixNano(),
	}, nil
}

func (m *GRPCClient) ExecuteStream(ctx context.Context, t Target, sink EventSink) (Result, error) {
	stream, err := m.client.ExecuteStream(ctx, &scanv1.ExecuteRequest{Host: t.Host, Params: t.Params})
	if err != nil {
		return Result{}, decodeExecutionError(err)
	}
	for {
		msg, recvErr := stream.Recv()
		if recvErr != nil {
			return Result{}, decodeExecutionError(recvErr)
		}
		if progress := msg.GetProgress(); progress != nil {
			if sink != nil {
				occurred := time.Now().UTC()
				if progress.GetOccurredAt() != nil {
					occurred = progress.GetOccurredAt().AsTime()
				}
				e := Event{Sequence: progress.GetSequence(), Level: progress.GetLevel(), Type: progress.GetType(), Message: progress.GetMessage(), Fields: progress.GetFields(), OccurredAt: occurred}
				if err := sink(e); err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if response := msg.GetResult(); response != nil {
			return resultFromProto(response), nil
		}
		return Result{}, fmt.Errorf("scan plugin returned an empty execute event")
	}
}

func resultFromProto(resp *scanv1.ExecuteResponse) Result {
	return Result{Capability: resp.GetCapability(), RawJSON: resp.GetRawJson(), StartedAtUnixNano: resp.GetStartedAtUnixNano(), FinishedAtUnixNano: resp.GetFinishedAtUnixNano()}
}

func (m *GRPCClient) Prepare(ctx context.Context, authToken string) error {
	_, err := m.client.Prepare(ctx, &scanv1.PrepareRequest{AuthToken: authToken})
	return err
}

func (m *GRPCClient) Describe(ctx context.Context) (Description, error) {
	r, e := m.client.Describe(ctx, &scanv1.DescribeRequest{})
	if e != nil {
		return Description{}, e
	}
	return Description{Capability: r.GetCapability(), CanonicalManifestJSON: append([]byte(nil), r.GetCanonicalManifestJson()...), ContractID: r.GetContractId(), ContractDigest: r.GetContractDigest(), ManifestSHA256: r.GetManifestSha256(), ProtocolVersion: r.GetProtocolVersion(), PluginVersion: r.GetPluginVersion(), SDKVersion: r.GetSdkVersion(), SourceCommit: r.GetSourceCommit(), Features: append([]string(nil), r.GetFeatures()...), RuntimeRequirements: cloneStrings(r.GetRuntimeRequirements())}, nil
}

func (m *GRPCClient) Check(ctx context.Context) (CheckResult, error) {
	r, err := m.client.Check(ctx, &scanv1.CheckRequest{})
	if err != nil {
		return CheckResult{}, err
	}
	issues := make([]CheckIssue, len(r.GetIssues()))
	for i, issue := range r.GetIssues() {
		issues[i] = CheckIssue{Code: issue.GetCode(), Message: issue.GetMessage()}
	}
	result := CheckResult{Status: CheckStatus(r.GetStatus()), Issues: issues}
	if err := validateCheckResult(result); err != nil {
		return CheckResult{}, status.Error(codes.FailedPrecondition, "plugin returned an invalid check result")
	}
	return result, nil
}
func (m *GRPCClient) ExecuteContract(ctx context.Context, q ContractRequest) (ContractResult, error) {
	if (q.ContractID == "") != (q.ContractDigest == "") {
		return ContractResult{}, status.Error(codes.InvalidArgument, "contract pins must be supplied together")
	}
	if q.ContractID == "" {
		return ContractResult{}, status.Error(codes.FailedPrecondition, "contract pins are required")
	}
	if !contract.ValidDigest(q.ContractDigest) {
		return ContractResult{}, status.Error(codes.InvalidArgument, "contract digest is malformed")
	}
	r, e := m.client.Execute(ctx, &scanv1.ExecuteRequest{Host: q.Target.Host, Params: q.Target.Params, ContractId: q.ContractID, ContractDigest: q.ContractDigest})
	if e != nil {
		return ContractResult{}, decodeExecutionError(e)
	}
	if r.GetContractId() != q.ContractID || r.GetContractDigest() != q.ContractDigest {
		return ContractResult{}, status.Error(codes.FailedPrecondition, "contract pin mismatch")
	}
	return fromContractProto(r)
}
func (m *GRPCClient) ExecuteStreamContract(ctx context.Context, q ContractRequest, sink EventSink) (ContractResult, error) {
	if (q.ContractID == "") != (q.ContractDigest == "") {
		return ContractResult{}, status.Error(codes.InvalidArgument, "contract pins must be supplied together")
	}
	if q.ContractID == "" {
		return ContractResult{}, status.Error(codes.FailedPrecondition, "contract pins are required")
	}
	if !contract.ValidDigest(q.ContractDigest) {
		return ContractResult{}, status.Error(codes.InvalidArgument, "contract digest is malformed")
	}
	st, e := m.client.ExecuteStream(ctx, &scanv1.ExecuteRequest{Host: q.Target.Host, Params: q.Target.Params, ContractId: q.ContractID, ContractDigest: q.ContractDigest})
	if e != nil {
		return ContractResult{}, decodeExecutionError(e)
	}
	for {
		ev, e := st.Recv()
		if e == io.EOF {
			return ContractResult{}, status.Error(codes.FailedPrecondition, "contract stream ended without a result")
		}
		if e != nil {
			return ContractResult{}, decodeExecutionError(e)
		}
		if p := ev.GetProgress(); p != nil {
			if sink != nil {
				occurred := time.Now().UTC()
				if p.GetOccurredAt() != nil {
					occurred = p.GetOccurredAt().AsTime()
				}
				if e = sink(Event{Sequence: p.GetSequence(), Level: p.GetLevel(), Type: p.GetType(), Message: p.GetMessage(), Fields: p.GetFields(), OccurredAt: occurred}); e != nil {
					return ContractResult{}, e
				}
			}
			continue
		}
		if r := ev.GetResult(); r != nil {
			if r.GetContractId() != q.ContractID || r.GetContractDigest() != q.ContractDigest {
				return ContractResult{}, status.Error(codes.FailedPrecondition, "contract pin mismatch")
			}
			result, err := fromContractProto(r)
			if err != nil {
				return ContractResult{}, err
			}
			if _, err := st.Recv(); err == io.EOF {
				return result, nil
			} else if err != nil {
				return ContractResult{}, err
			}
			return ContractResult{}, status.Error(codes.FailedPrecondition, "contract stream returned events after its result")
		}
		return ContractResult{}, status.Error(codes.FailedPrecondition, "contract stream returned an empty event")
	}
}
func fromContractProto(r *scanv1.ExecuteResponse) (ContractResult, error) {
	out := make([]contract.NamedOutput, 0, len(r.GetOutputs()))
	for _, o := range r.GetOutputs() {
		x := contract.NamedOutput{Name: o.GetName()}
		for _, v := range o.GetValues() {
			if v == nil || v.GetValue() == nil {
				return ContractResult{}, status.Error(codes.FailedPrecondition, "malformed typed output")
			}
			switch z := v.GetValue().(type) {
			case *scanv1.TypedValue_Domain:
				q, e := contract.Domain(z.Domain)
				if e != nil {
					return ContractResult{}, status.Error(codes.FailedPrecondition, "malformed typed output")
				}
				x.Values = append(x.Values, q)
			case *scanv1.TypedValue_Host:
				q, e := contract.Host(z.Host)
				if e != nil {
					return ContractResult{}, status.Error(codes.FailedPrecondition, "malformed typed output")
				}
				x.Values = append(x.Values, q)
			case *scanv1.TypedValue_Url:
				q, e := contract.URL(z.Url)
				if e != nil {
					return ContractResult{}, status.Error(codes.FailedPrecondition, "malformed typed output")
				}
				x.Values = append(x.Values, q)
			default:
				return ContractResult{}, status.Error(codes.FailedPrecondition, "malformed typed output")
			}
		}
		out = append(out, x)
	}
	return ContractResult{Result: resultFromProto(r), Outputs: out, ContractID: r.GetContractId(), ContractDigest: r.GetContractDigest()}, nil
}

// gRPCServer is the plugin-side bridge from the proto service to the Scanner.
type gRPCServer struct {
	scanv1.UnimplementedScanPluginServer
	impl     Scanner
	contract *contract.Descriptor
	options  ManifestOptions
}

func (m *gRPCServer) Capability(ctx context.Context, _ *scanv1.CapabilityRequest) (*scanv1.CapabilityResponse, error) {
	c, err := m.impl.Capability(ctx)
	if err != nil {
		return nil, err
	}
	return &scanv1.CapabilityResponse{Capability: c}, nil
}

func (m *gRPCServer) Execute(ctx context.Context, req *scanv1.ExecuteRequest) (*scanv1.ExecuteResponse, error) {
	if req.GetContractId() != "" || req.GetContractDigest() != "" {
		r, e := m.executeContract(ctx, req, false, nil)
		return r, executionStatusError(e)
	}
	res, err := m.impl.Execute(ctx, Target{Host: req.GetHost(), Params: req.GetParams()})
	if err != nil {
		return nil, executionStatusError(err)
	}
	return &scanv1.ExecuteResponse{
		Capability:         res.Capability,
		RawJson:            res.RawJSON,
		StartedAtUnixNano:  res.StartedAtUnixNano,
		FinishedAtUnixNano: res.FinishedAtUnixNano,
	}, nil
}

func (m *gRPCServer) ExecuteStream(req *scanv1.ExecuteRequest, stream scanv1.ScanPlugin_ExecuteStreamServer) error {
	if req.GetContractId() != "" || req.GetContractDigest() != "" {
		res, e := m.executeContract(stream.Context(), req, true, func(e Event) error {
			if e.OccurredAt.IsZero() {
				e.OccurredAt = time.Now().UTC()
			}
			return stream.Send(&scanv1.ExecuteEvent{Payload: &scanv1.ExecuteEvent_Progress{Progress: &scanv1.ProgressEvent{Sequence: e.Sequence, Level: e.Level, Type: e.Type, Message: e.Message, Fields: boundedFields(e.Fields), OccurredAt: timestamppb.New(e.OccurredAt)}}})
		})
		if e != nil {
			return executionStatusError(e)
		}
		return stream.Send(&scanv1.ExecuteEvent{Payload: &scanv1.ExecuteEvent_Result{Result: res}})
	}
	res, err := m.impl.ExecuteStream(stream.Context(), Target{Host: req.GetHost(), Params: req.GetParams()}, func(event Event) error {
		if event.OccurredAt.IsZero() {
			event.OccurredAt = time.Now().UTC()
		}
		return stream.Send(&scanv1.ExecuteEvent{Payload: &scanv1.ExecuteEvent_Progress{Progress: &scanv1.ProgressEvent{Sequence: event.Sequence, Level: event.Level, Type: event.Type, Message: event.Message, Fields: boundedFields(event.Fields), OccurredAt: timestamppb.New(event.OccurredAt)}}})
	})
	if err != nil {
		return executionStatusError(err)
	}
	return stream.Send(&scanv1.ExecuteEvent{Payload: &scanv1.ExecuteEvent_Result{Result: &scanv1.ExecuteResponse{Capability: res.Capability, RawJson: res.RawJSON, StartedAtUnixNano: res.StartedAtUnixNano, FinishedAtUnixNano: res.FinishedAtUnixNano}}})
}

func (m *gRPCServer) Describe(context.Context, *scanv1.DescribeRequest) (*scanv1.DescribeResponse, error) {
	if m.contract == nil {
		return nil, status.Error(codes.Unimplemented, "manifest unavailable")
	}
	metadata := m.options.BuildMetadata
	return &scanv1.DescribeResponse{Capability: m.contract.Manifest().Capability, CanonicalManifestJson: m.contract.CanonicalJSON(), ContractId: m.contract.Manifest().ContractID, ContractDigest: m.contract.Digest(), ManifestSha256: m.contract.ManifestDigest(), ProtocolVersion: ContractProtocolVersion, PluginVersion: metadata.PluginVersion, SdkVersion: metadata.SDKVersion, SourceCommit: metadata.SourceCommit, Features: append([]string(nil), metadata.Features...), RuntimeRequirements: cloneStrings(metadata.RuntimeRequirements)}, nil
}

func (m *gRPCServer) Check(ctx context.Context, _ *scanv1.CheckRequest) (*scanv1.CheckResponse, error) {
	checker, ok := m.impl.(Checker)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "check unavailable")
	}
	result, err := checker.Check(ctx)
	if err != nil {
		return nil, contextStatusError(err)
	}
	if err := validateCheckResult(result); err != nil {
		return nil, status.Error(codes.Internal, "plugin returned an invalid check result")
	}
	issues := make([]*scanv1.CheckIssue, len(result.Issues))
	for i, issue := range result.Issues {
		issues[i] = &scanv1.CheckIssue{Code: issue.Code, Message: issue.Message}
	}
	return &scanv1.CheckResponse{Status: string(result.Status), Issues: issues}, nil
}
func (m *gRPCServer) executeContract(ctx context.Context, req *scanv1.ExecuteRequest, stream bool, sink EventSink) (*scanv1.ExecuteResponse, error) {
	if (req.GetContractId() == "") != (req.GetContractDigest() == "") {
		return nil, status.Error(codes.InvalidArgument, "contract pins must be supplied together")
	}
	if m.contract == nil {
		return nil, status.Error(codes.FailedPrecondition, "manifest unavailable")
	}
	if !contract.ValidDigest(req.GetContractDigest()) {
		return nil, status.Error(codes.InvalidArgument, "contract digest is malformed")
	}
	d := m.contract.Manifest()
	if req.GetContractId() != d.ContractID || req.GetContractDigest() != m.contract.Digest() {
		return nil, status.Error(codes.FailedPrecondition, "contract pin mismatch")
	}
	if len(d.Inputs) != 1 || d.Inputs[0].Name != "target" || d.Inputs[0].Cardinality != "one" {
		return nil, status.Error(codes.FailedPrecondition, "unsupported input contract")
	}
	var canonicalTarget string
	for _, t := range d.Inputs[0].AcceptedTypes {
		var e error
		switch t {
		case "domain/v1":
			v, err := contract.Domain(req.GetHost())
			e = err
			if e == nil {
				canonicalTarget = v.String()
			}
		case "host/v1":
			v, err := contract.Host(req.GetHost())
			e = err
			if e == nil {
				canonicalTarget = v.String()
			}
		case "url/v1":
			v, err := contract.URL(req.GetHost())
			e = err
			if e == nil {
				canonicalTarget = v.String()
			}
		}
		if e == nil {
			break
		}
	}
	if canonicalTarget == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid target")
	}
	params, e := contract.NormalizeParameters(&d, req.GetParams())
	if e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	target := Target{Host: canonicalTarget, Params: params}
	if m.options.TargetMapper != nil {
		target, e = m.options.TargetMapper(target)
		if e != nil {
			return nil, status.Error(codes.InvalidArgument, "target conversion failed")
		}
	}
	var res Result
	if stream {
		res, e = m.impl.ExecuteStream(ctx, target, sink)
	} else {
		res, e = m.impl.Execute(ctx, target)
	}
	if e != nil {
		return nil, e
	}
	if res.Capability != d.Capability {
		return nil, status.Error(codes.FailedPrecondition, "capability mismatch")
	}
	if m.options.OutputMapper == nil && len(d.Outputs) > 0 {
		return nil, status.Error(codes.FailedPrecondition, "output mapper unavailable")
	}
	var outs []contract.NamedOutput
	if m.options.OutputMapper != nil {
		outs, e = m.options.OutputMapper(target, res)
		if e != nil {
			return nil, status.Error(codes.FailedPrecondition, "output conversion failed")
		}
	}
	outs, e = contract.ValidateOutputs(d, outs)
	if e != nil {
		return nil, status.Error(codes.FailedPrecondition, e.Error())
	}
	return &scanv1.ExecuteResponse{Capability: res.Capability, RawJson: res.RawJSON, StartedAtUnixNano: res.StartedAtUnixNano, FinishedAtUnixNano: res.FinishedAtUnixNano, Outputs: outputsProto(outs), ContractId: d.ContractID, ContractDigest: m.contract.Digest()}, nil
}
func outputsProto(xs []contract.NamedOutput) []*scanv1.NamedOutput {
	out := make([]*scanv1.NamedOutput, 0, len(xs))
	for _, x := range xs {
		p := &scanv1.NamedOutput{Name: x.Name}
		for _, v := range x.Values {
			q := &scanv1.TypedValue{}
			switch v.Type() {
			case "domain/v1":
				q.Value = &scanv1.TypedValue_Domain{Domain: v.String()}
			case "host/v1":
				q.Value = &scanv1.TypedValue_Host{Host: v.String()}
			case "url/v1":
				q.Value = &scanv1.TypedValue_Url{Url: v.String()}
			}
			p.Values = append(p.Values, q)
		}
		out = append(out, p)
	}
	return out
}

func boundedFields(fields map[string]string) map[string]string {
	const maxFields, maxValue = 16, 256
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		if len(out) >= maxFields {
			break
		}
		if len(key) > maxValue {
			key = key[:maxValue]
		}
		if key != "line" && len(value) > maxValue {
			value = value[:maxValue]
		}
		out[key] = value
	}
	return out
}

func cloneStrings(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func safeCode(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value[1:] {
		if char < 'a' || char > 'z' {
			if char < '0' || char > '9' {
				if char != '_' && char != '-' {
					return false
				}
			}
		}
	}
	return true
}

func safeMessage(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func validateCheckResult(result CheckResult) error {
	if result.Status != CheckStatusOK && result.Status != CheckStatusDegraded && result.Status != CheckStatusUnhealthy {
		return errors.New("invalid check status")
	}
	if len(result.Issues) > 32 {
		return errors.New("too many check issues")
	}
	for _, issue := range result.Issues {
		if !safeCode(issue.Code) || !safeMessage(issue.Message) {
			return errors.New("invalid check issue")
		}
	}
	return nil
}

func validateExecutionError(executionError *ExecutionError) bool {
	if executionError == nil || !safeCode(executionError.Code) || !safeMessage(executionError.Message) || len(executionError.Details) > 16 {
		return false
	}
	for key, value := range executionError.Details {
		if !safeCode(key) || len(value) > 256 || !utf8.ValidString(value) {
			return false
		}
		for _, char := range value {
			if char < 0x20 || char == 0x7f {
				return false
			}
		}
	}
	return true
}

var buildVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func validateBuildMetadata(metadata BuildMetadata) error {
	empty := metadata.PluginVersion == "" && metadata.SDKVersion == "" && metadata.SourceCommit == "" && metadata.Features == nil && metadata.RuntimeRequirements == nil
	if empty {
		return nil
	}
	if !buildVersionPattern.MatchString(metadata.PluginVersion) || !buildVersionPattern.MatchString(metadata.SDKVersion) || len(metadata.SourceCommit) != 40 {
		return errors.New("invalid plugin build identity")
	}
	for _, char := range metadata.SourceCommit {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return errors.New("invalid plugin build identity")
		}
	}
	if metadata.Features == nil || metadata.RuntimeRequirements == nil || len(metadata.Features) > 32 || len(metadata.RuntimeRequirements) > 32 {
		return errors.New("invalid plugin build metadata")
	}
	seenFeatures := make(map[string]struct{}, len(metadata.Features))
	for i, feature := range metadata.Features {
		if !safeCode(feature) {
			return errors.New("invalid plugin build feature")
		}
		if i > 0 && metadata.Features[i-1] >= feature {
			return errors.New("plugin build features are not in canonical order")
		}
		if _, duplicate := seenFeatures[feature]; duplicate {
			return errors.New("duplicate plugin build feature")
		}
		seenFeatures[feature] = struct{}{}
	}
	for key, value := range metadata.RuntimeRequirements {
		if !safeCode(key) || value == "" || len(value) > 256 || !utf8.ValidString(value) {
			return errors.New("invalid plugin runtime requirement")
		}
		for _, char := range value {
			if char < 0x20 || char == 0x7f {
				return errors.New("invalid plugin runtime requirement")
			}
		}
	}
	return nil
}

func contextStatusError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	return err
}

func executionStatusError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	executionError, ok := AsExecutionError(err)
	if !ok {
		return err
	}
	if !validateExecutionError(executionError) {
		return status.Error(codes.Internal, "plugin returned an invalid execution error")
	}
	detail := &scanv1.ExecutionErrorDetail{Code: executionError.Code, Message: executionError.Message, Retryable: executionError.Retryable, Details: cloneStrings(executionError.Details)}
	withDetails, detailErr := status.New(codes.Unknown, executionError.Error()).WithDetails(detail)
	if detailErr != nil {
		return status.Error(codes.Internal, "could not encode execution error")
	}
	return withDetails.Err()
}

func decodeExecutionError(err error) error {
	if err == nil {
		return nil
	}
	grpcStatus, ok := status.FromError(err)
	if !ok || grpcStatus.Code() == codes.Canceled || grpcStatus.Code() == codes.DeadlineExceeded {
		return err
	}
	for _, detail := range grpcStatus.Details() {
		if executionDetail, ok := detail.(*scanv1.ExecutionErrorDetail); ok {
			executionError := &ExecutionError{Code: executionDetail.GetCode(), Message: executionDetail.GetMessage(), Retryable: executionDetail.GetRetryable(), Details: cloneStrings(executionDetail.GetDetails()), status: grpcStatus}
			if validateExecutionError(executionError) {
				return executionError
			}
			return err
		}
	}
	return err
}

func (m *gRPCServer) Prepare(ctx context.Context, req *scanv1.PrepareRequest) (*scanv1.PrepareResponse, error) {
	if err := m.impl.Prepare(ctx, req.GetAuthToken()); err != nil {
		return nil, err
	}
	return &scanv1.PrepareResponse{}, nil
}
