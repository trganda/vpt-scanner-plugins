package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	return contract.Manifest{ManifestVersion: contract.ManifestVersion, Capability: string(contract.CapabilitySubdomain), ContractID: "vpt/subdomain/v1", Display: &contract.Display{Name: "Subdomain discovery", Description: "Discover subdomains for a domain."}, Inputs: []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeDomain)}, Cardinality: string(contract.CardinalityOne)}}, Outputs: []contract.Output{{Name: "subdomains", Type: string(contract.ValueTypeHost), Cardinality: string(contract.CardinalityMany)}}, Parameters: []contract.Parameter{}}
}
