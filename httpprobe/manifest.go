package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"
import "github.com/trganda/vpt-scanner-plugins/sdk/runtimeconfig"

func manifest() contract.Manifest {
	defaultPorts := "80,443"
	t := func(s string) *string { return &s }
	i := func(n int64) *int64 { return &n }
	b := func(v bool) *string { return t(map[bool]string{true: "true", false: "false"}[v]) }
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilityHTTPProbe), ContractID: "vpt/httpprobe/v1", Display: &contract.Display{Name: "HTTP probe", Description: "Probe HTTP services on a host."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeHost)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "ports", Kind: "port_set", Default: &defaultPorts}, {Name: "request_timeout_seconds", Kind: "integer", Default: t("10"), Minimum: i(1), Maximum: i(300)}, {Name: "methods", Kind: "string_list", ItemsEnum: methods}, {Name: "follow_redirects", Kind: "boolean", Default: b(true)}, {Name: "tech_detect", Kind: "boolean", Default: b(true)}, {Name: "asn", Kind: "boolean", Default: b(false)}}}
}
func legacyManifest() contract.Manifest {
	p := "80,443"
	return contract.Manifest{ManifestVersion: 1, Capability: "httpprobe", ContractID: "vpt/httpprobe/v1", Display: &contract.Display{Name: "HTTP probe", Description: "Probe HTTP services on a host."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{"host/v1"}, Cardinality: "one"}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "ports", Kind: "port_set", Default: &p}}}
}
func runtimeManifest() runtimeconfig.Manifest {
	t := func(s string) *string { return &s }
	i := func(n int64) *int64 { return &n }
	return runtimeconfig.Manifest{ManifestVersion: 1, Capability: "httpprobe", Parameters: []runtimeconfig.Parameter{{Name: "threads", Kind: "integer", Scope: runtimeconfig.ScopePlugin, Default: t("25"), Minimum: i(1), Maximum: i(1000)}, {Name: "max_run_time_seconds", Kind: "integer", Scope: runtimeconfig.ScopePlugin, Default: t("300"), Minimum: i(1), Maximum: i(1500)}, {Name: "max_concurrent_activities", Kind: "integer", Scope: runtimeconfig.ScopeWorker, Default: t("1"), Minimum: i(1), Maximum: i(1)}}}
}
