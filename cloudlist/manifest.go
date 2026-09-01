package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	zero := 0
	one := int64(1)
	defaultMaxRunTime := "600"
	return contract.Manifest{
		ManifestVersion: contract.ManifestVersion,
		Capability:      string(contract.CapabilityCloudlist),
		ContractID:      "vpt/cloudlist/v1",
		Display:         &contract.Display{Name: "Cloud asset discovery", Description: "Discover configured cloud assets scoped to a domain."},
		Inputs:          []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeDomain)}, Cardinality: string(contract.CardinalityOne)}},
		Outputs:         []contract.Output{{Name: "hosts", Type: string(contract.ValueTypeHost), Cardinality: string(contract.CardinalityMany)}},
		Parameters: []contract.Parameter{
			{Name: "max_run_time_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultMaxRunTime, Minimum: &one},
			{Name: "providers", Kind: string(contract.ParameterKindStringList), MinItems: &zero},
			{Name: "provider_ids", Kind: string(contract.ParameterKindStringList), MinItems: &zero},
			{Name: "services", Kind: string(contract.ParameterKindStringList), MinItems: &zero},
		},
	}
}
