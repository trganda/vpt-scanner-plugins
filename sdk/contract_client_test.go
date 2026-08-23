package sdk

import (
	"testing"

	scanv1 "github.com/trganda/vpt-scanner-plugins/sdk/proto/scan/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFromContractProtoRejectsMalformedTypedValues(t *testing.T) {
	responses := []*scanv1.ExecuteResponse{
		{Outputs: []*scanv1.NamedOutput{{Name: "hosts", Values: []*scanv1.TypedValue{{}}}}},
		{Outputs: []*scanv1.NamedOutput{{Name: "hosts", Values: []*scanv1.TypedValue{{Value: &scanv1.TypedValue_Host{Host: "bad host"}}}}}},
	}
	for _, response := range responses {
		if _, err := fromContractProto(response); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("malformed typed value returned %v", err)
		}
	}
}
