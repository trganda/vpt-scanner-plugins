package main

import "github.com/trganda/vpt-scanner-plugins/sdk/contract"

func manifest() contract.Manifest {
	zero := int64(0)
	one := int64(1)
	zeroItems := 0
	defaultTimeout := "10"
	defaultMaxRunTime := "300"
	defaultConcurrency := "10"
	defaultRateLimit := "150"
	defaultMaxDepth := "3"
	defaultStrategy := "depth-first"
	defaultRetries := "1"
	defaultKnownFiles := "none"
	defaultMaxDomainPages := "1000"
	defaultFieldScope := "rdn"
	defaultFalse := "false"
	defaultSimilarThreshold := "10"
	defaultDelay := "0"
	return contract.Manifest{
		ManifestVersion: contract.ManifestVersion,
		Capability:      string(contract.CapabilityKatana),
		ContractID:      "vpt/katana/v1",
		Display:         &contract.Display{Name: "Web crawler", Description: "Crawl an in-scope HTTP URL and discover web endpoints."},
		Inputs:          []contract.Input{{Name: "target", AcceptedTypes: []string{string(contract.ValueTypeURL)}, Cardinality: string(contract.CardinalityOne)}},
		Outputs:         []contract.Output{{Name: "urls", Type: string(contract.ValueTypeURL), Cardinality: string(contract.CardinalityMany)}},
		Parameters: []contract.Parameter{
			{Name: "timeout_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultTimeout, Minimum: &one},
			{Name: "max_run_time_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultMaxRunTime, Minimum: &one},
			{Name: "concurrency", Kind: string(contract.ParameterKindInteger), Default: &defaultConcurrency, Minimum: &one},
			{Name: "rate_limit", Kind: string(contract.ParameterKindInteger), Default: &defaultRateLimit, Minimum: &one},
			{Name: "max_depth", Kind: string(contract.ParameterKindInteger), Default: &defaultMaxDepth, Minimum: &one},
			{Name: "scrape_js", Kind: string(contract.ParameterKindBoolean), Default: &defaultFalse},
			{Name: "strategy", Kind: string(contract.ParameterKindEnum), Default: &defaultStrategy, Enum: []string{"depth-first", "breadth-first"}},
			{Name: "retries", Kind: string(contract.ParameterKindInteger), Default: &defaultRetries, Minimum: &zero},
			{Name: "known_files", Kind: string(contract.ParameterKindEnum), Default: &defaultKnownFiles, Enum: []string{"none", "all", "robotstxt", "sitemapxml"}},
			{Name: "max_domain_pages", Kind: string(contract.ParameterKindInteger), Default: &defaultMaxDomainPages, Minimum: &one},
			{Name: "field_scope", Kind: string(contract.ParameterKindEnum), Default: &defaultFieldScope, Enum: []string{"rdn", "fqdn"}},
			{Name: "ignore_query_params", Kind: string(contract.ParameterKindBoolean), Default: &defaultFalse},
			{Name: "filter_similar", Kind: string(contract.ParameterKindBoolean), Default: &defaultFalse},
			{Name: "filter_similar_threshold", Kind: string(contract.ParameterKindInteger), Default: &defaultSimilarThreshold, Minimum: &one},
			{Name: "disable_redirects", Kind: string(contract.ParameterKindBoolean), Default: &defaultFalse},
			{Name: "extension_filter", Kind: string(contract.ParameterKindStringList), MinItems: &zeroItems},
			{Name: "delay_seconds", Kind: string(contract.ParameterKindInteger), Default: &defaultDelay, Minimum: &zero},
		},
	}
}
