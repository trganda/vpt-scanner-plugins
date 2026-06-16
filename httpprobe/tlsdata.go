package main

import "time"

// TLSData is the curated, SDK-free TLS-grab subset stored in
// ProbeResult.TLS. Its JSON tags must stay byte-identical to
// internal/core/asset.TLSData (the host decodes the probe payload against that
// type via result_processor.rawProbe) — this is the cross-process contract.
type TLSData struct {
	Version  string `json:"version,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	SNI      string `json:"sni,omitempty"`
	JA3Hash  string `json:"ja3_hash,omitempty"`
	JA3SHash string `json:"ja3s_hash,omitempty"`
	JARMHash string `json:"jarm_hash,omitempty"`

	// Leaf-certificate fields.
	NotBefore         time.Time `json:"not_before,omitzero"`
	NotAfter          time.Time `json:"not_after,omitzero"`
	SubjectCN         string    `json:"subject_cn,omitempty"`
	SubjectOrg        []string  `json:"subject_org,omitempty"`
	SubjectAN         []string  `json:"subject_an,omitempty"`
	IssuerCN          string    `json:"issuer_cn,omitempty"`
	IssuerOrg         []string  `json:"issuer_org,omitempty"`
	Serial            string    `json:"serial,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256,omitempty"`

	SelfSigned   bool `json:"self_signed,omitempty"`
	Expired      bool `json:"expired,omitempty"`
	MisMatched   bool `json:"mismatched,omitempty"`
	WildcardCert bool `json:"wildcard_certificate,omitempty"`
}
