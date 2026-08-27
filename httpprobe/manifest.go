package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	defaultPorts := "80,443"
	defaultThreads := "25"
	defaultTimeout := "10"
	defaultMaxRunTime := "300"
	trueValue := "true"
	falseValue := "false"
	one := int64(1)
	zero := 0
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilityHTTPProbe), ContractID: "vpt/httpprobe/v1", Display: &contract.Display{Name: "HTTP probe", Description: "Probe HTTP services on a host."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeHost)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "ports", Kind: string(contract.ParameterKindPortSet), Default: &defaultPorts}, {Name: "threads", Kind: string(contract.ParameterKindInteger), Default: &defaultThreads, Minimum: &one}, {Name: "timeout_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultTimeout, Minimum: &one}, {Name: "max_run_time_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultMaxRunTime, Minimum: &one}, {Name: "methods", Kind: string(contract.ParameterKindStringList), MinItems: &zero}, {Name: "follow_redirects", Kind: string(contract.ParameterKindBoolean), Default: &trueValue}, {Name: "tech_detect", Kind: string(contract.ParameterKindBoolean), Default: &trueValue}, {Name: "asn", Kind: string(contract.ParameterKindBoolean), Default: &falseValue}}}
}
