package sdk

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("boundedFields", func() {
	It("preserves the line field", func() {
		line := make([]byte, 300)
		for i := range line {
			line[i] = 'x'
		}
		got := boundedFields(map[string]string{"line": string(line), "regular": string(line)})
		Expect(got["line"]).To(HaveLen(300))
		Expect(got["regular"]).To(HaveLen(256))
	})
})
