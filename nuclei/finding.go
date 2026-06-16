package main

import "time"

// Finding is a single nuclei scan result stored in ScanResult.Raw["findings"].
// Its JSON tags are the cross-process contract the host's result processor
// (rawFinding) decodes against — keep them in sync.
type Finding struct {
	TemplateID   string    `json:"template_id"`
	TemplateName string    `json:"template_name"`
	Severity     string    `json:"severity"`
	Host         string    `json:"host"`
	Matched      string    `json:"matched_at"`
	Tags         []string  `json:"tags"`
	Type         string    `json:"type"`
	Description  string    `json:"description,omitempty"`
	CVEIDs       []string  `json:"cve_ids"`
	Timestamp    time.Time `json:"timestamp"`
}
