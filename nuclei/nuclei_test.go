package main

import "testing"

func TestIntParam(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
		key    string
		def    int
		want   int
	}{
		{"missing", nil, "x", 5, 5},
		{"present", map[string]string{"x": "7"}, "x", 5, 7},
		{"invalid", map[string]string{"x": "nope"}, "x", 5, 5},
		{"negative allowed by contract", map[string]string{"x": "-1"}, "x", 5, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := intParam(tc.params, tc.key, tc.def); got != tc.want {
				t.Fatalf("intParam = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFiltersFromParams(t *testing.T) {
	f := filtersFromParams(map[string]string{"tags": "cve, rce", "severity": "high", "ids": "CVE-1,CVE-2"})
	if len(f.Tags) != 2 || f.Tags[0] != "cve" || f.Tags[1] != "rce" {
		t.Fatalf("tags = %#v", f.Tags)
	}
	if f.Severity != "high" {
		t.Fatalf("severity = %q", f.Severity)
	}
	if len(f.IDs) != 2 || f.IDs[0] != "CVE-1" || f.IDs[1] != "CVE-2" {
		t.Fatalf("ids = %#v", f.IDs)
	}
}
