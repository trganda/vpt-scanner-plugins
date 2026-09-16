package sdk

import (
	"context"
	"strings"
	"testing"

	scanv1 "github.com/trganda/vpt-scanner-plugins/sdk/proto/scan/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type checkClient struct {
	scanv1.ScanPluginClient
	response *scanv1.CheckResponse
}

func (c checkClient) Check(context.Context, *scanv1.CheckRequest, ...grpc.CallOption) (*scanv1.CheckResponse, error) {
	return c.response, nil
}

func TestGRPCClientRejectsMalformedCheckResults(t *testing.T) {
	cases := []*scanv1.CheckResponse{
		{Status: "unknown"},
		{Status: string(CheckStatusOK), Issues: []*scanv1.CheckIssue{{Code: "BAD", Message: "bad code"}}},
		{Status: string(CheckStatusOK), Issues: []*scanv1.CheckIssue{{Code: "bad_message", Message: "line\nbreak"}}},
	}
	for _, response := range cases {
		client := &GRPCClient{client: checkClient{response: response}}
		if _, err := client.Check(context.Background()); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("Check error code = %s, want FailedPrecondition", status.Code(err))
		}
	}
}

func TestDecodeExecutionErrorRejectsMalformedDetails(t *testing.T) {
	detail := &scanv1.ExecutionErrorDetail{Code: "tool_failed", Message: "tool failed", Details: map[string]string{"detail": strings.Repeat("x", 257)}}
	withDetails, err := status.New(codes.Unknown, "tool failed").WithDetails(detail)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeExecutionError(withDetails.Err())
	if _, ok := AsExecutionError(decoded); ok {
		t.Fatal("malformed execution detail was trusted")
	}
}
