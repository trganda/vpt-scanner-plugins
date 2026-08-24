package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	defaultPorts := "80,443"
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilityHTTPProbe), ContractID: "vpt/httpprobe/v1", Display: &contract.Display{Name: "HTTP probe", Description: "Probe HTTP services on a host."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeHost)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "ports", Kind: string(contract.ParameterKindPortSet), Default: &defaultPorts}}}
}
