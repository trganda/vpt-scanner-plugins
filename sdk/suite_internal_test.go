package sdk

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSDKInternal(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SDK Internal Suite")
}
