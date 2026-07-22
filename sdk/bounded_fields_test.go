package sdk

import "testing"

func TestBoundedFieldsPreservesLine(t *testing.T) {
	line := make([]byte, 300)
	for i := range line {
		line[i] = 'x'
	}
	got := boundedFields(map[string]string{
		"line":    string(line),
		"regular": string(line),
	})
	if len(got["line"]) != 300 {
		t.Fatalf("line length = %d, want 300", len(got["line"]))
	}
	if len(got["regular"]) != 256 {
		t.Fatalf("regular length = %d, want 256", len(got["regular"]))
	}
}
