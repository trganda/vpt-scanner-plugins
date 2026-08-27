package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	all := "all"
	zeroItems := 0
	one := int64(1)
	zeroValue := int64(0)
	defaultTemplateConcurrency := "25"
	defaultHostConcurrency := "25"
	defaultNetworkTimeout := "10"
	defaultNetworkRetries := "2"
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilityVuln), ContractID: "vpt/vuln/v1", Display: &contract.Display{Name: "Vulnerability scan", Description: "Scan a host or URL for vulnerabilities."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeHost), string(contract.ValueTypeURL)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "tags", Kind: string(contract.ParameterKindStringList), MinItems: &zeroItems}, {Name: "ids", Kind: string(contract.ParameterKindStringList), MinItems: &zeroItems}, {Name: "severity", Kind: string(contract.ParameterKindEnum), Default: &all, Enum: []string{"all", "info", "low", "medium", "high", "critical"}}, {Name: "template_concurrency", Kind: string(contract.ParameterKindInteger), Default: &defaultTemplateConcurrency, Minimum: &one}, {Name: "host_concurrency", Kind: string(contract.ParameterKindInteger), Default: &defaultHostConcurrency, Minimum: &one}, {Name: "network_timeout", Kind: string(contract.ParameterKindInteger), Default: &defaultNetworkTimeout, Minimum: &one}, {Name: "network_retries", Kind: string(contract.ParameterKindInteger), Default: &defaultNetworkRetries, Minimum: &zeroValue}}}
}
