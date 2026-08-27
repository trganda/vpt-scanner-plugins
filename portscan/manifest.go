package main

import (
	"github.com/trganda/vpt-scanner-plugins/sdk/contract"
)

func manifest() contract.Manifest {
	defaultPorts := "100"
	defaultTimeout := "300"
	one := int64(1)
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilityPortscan), ContractID: "vpt/portscan/v1", Display: &contract.Display{Name: "Port scan", Description: "Scan TCP ports on a host."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeHost)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "ports", Kind: string(contract.ParameterKindPortSet), Default: &defaultPorts}, {Name: "timeout_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultTimeout, Minimum: &one}}}
}
