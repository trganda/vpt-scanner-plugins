package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	zero := 0
	one := int64(1)
	defaultThreads := "10"
	defaultTimeout := "30"
	defaultMaxRunTime := "600"
	defaultAllSources := "false"
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilitySubdomain), ContractID: "vpt/subdomain/v1", Display: &contract.Display{Name: "Subdomain discovery", Description: "Discover subdomains for a domain."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeDomain)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{{Name: "subdomains", Type: string(contract.ValueTypeHost), Cardinality: string(contract.CardinalityMany)}}, Parameters: []contract.Parameter{{Name: "threads", Kind: string(contract.ParameterKindInteger), Default: &defaultThreads, Minimum: &one}, {Name: "timeout_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultTimeout, Minimum: &one}, {Name: "max_run_time_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultMaxRunTime, Minimum: &one}, {Name: "all_sources", Kind: string(contract.ParameterKindBoolean), Default: &defaultAllSources}, {Name: "sources", Kind: string(contract.ParameterKindStringList), MinItems: &zero}, {Name: "exclude_sources", Kind: string(contract.ParameterKindStringList), MinItems: &zero}, {Name: "resolvers", Kind: string(contract.ParameterKindStringList), MinItems: &zero}}}
}
