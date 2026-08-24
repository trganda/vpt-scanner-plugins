package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	all := "all"
	zero := 0
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilityVuln), ContractID: "vpt/vuln/v1", Display: &contract.Display{Name: "Vulnerability scan", Description: "Scan a host or URL for vulnerabilities."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeHost), string(contract.ValueTypeURL)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{}, Parameters: []contract.Parameter{{Name: "tags", Kind: string(contract.ParameterKindStringList), MinItems: &zero}, {Name: "ids", Kind: string(contract.ParameterKindStringList), MinItems: &zero}, {Name: "severity", Kind: string(contract.ParameterKindEnum), Default: &all, Enum: []string{"all", "info", "low", "medium", "high", "critical"}}}}
}
