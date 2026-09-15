// Package model defines the core, provider-agnostic types shared across the
// collector: scopes, artifacts, exposure records, the coverage ledger, and the
// Evidence Bundle manifest.
package model

import "time"

// Scope identifies WHERE a fact was collected. Global resources (IAM, etc.) set
// Global=true and leave Region empty.
type Scope struct {
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Region   string `json:"region,omitempty"`
	Global   bool   `json:"global,omitempty"`
}

// Artifact is one collected resource, normalized. NodeType (from RAGE
// vocab/node-types.json) is how the bundle reconciles to the graph.
type Artifact struct {
	Provider     string            `json:"provider"`
	Account      string            `json:"account"`
	Scope        Scope             `json:"scope"`
	ResourceType string            `json:"resource_type"` // e.g. aws:lambda:function
	NodeType     string            `json:"node_type,omitempty"`
	NativeID     string            `json:"native_id"`
	ARN          string            `json:"arn,omitempty"`
	Attributes   map[string]any    `json:"attributes,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	CollectedBy  []string          `json:"collected_by,omitempty"` // operations that produced it
	CapturedAt   time.Time         `json:"captured_at"`
	EvidenceRef  string            `json:"evidence_ref,omitempty"` // blob://<sha256> for large payloads
}

// ExposureHit is a credential/secret surfaced by a read_api exposure probe.
// EmitsHint (a real edge name) is how it reconciles to the exposure model.
type ExposureHit struct {
	SiteID     string `json:"site_id"`
	ResourceID string `json:"resource_id"`
	Provider   string `json:"provider"`
	Scope      Scope  `json:"scope"`
	EmitsHint  string `json:"emits_hint"`
	Severity   string `json:"severity"`
	Location   string `json:"location"`
	Found      bool   `json:"found"`
	ValueRef   string `json:"value_ref,omitempty"` // salted-hash fingerprint (dedup / integrity)
	Value      string `json:"value,omitempty"`     // the actual captured value (capped); the loot
}

// Surface is a known credential-exposure surface that was NOT invoked (any
// access_mode other than read_api) — recorded for completeness, never called.
type Surface struct {
	SiteID     string `json:"site_id"`
	ResourceID string `json:"resource_id"`
	AccessMode string `json:"access_mode"`
	Location   string `json:"location"`
	EmitsHint  string `json:"emits_hint"`
	Severity   string `json:"severity"`
}

// Fact is a normalized relationship/policy/network fact that the engine turns
// into a graph EDGE. EdgeHint names the edge
// type it feeds (CanAssume, HasPolicy, MemberOf, CrossAccountTrust, CanReachPort,
// PeeredWith, RoutesTo, ...). Kind groups facts for the engine's normalizer.
type Fact struct {
	Kind       string         `json:"kind"`
	EdgeHint   string         `json:"edge_hint"`
	Provider   string         `json:"provider"`
	Scope      Scope          `json:"scope"`
	Source     string         `json:"source"`           // e.g. principal/resource arn
	Target     string         `json:"target,omitempty"` // e.g. role/group/policy arn, cidr, vpc
	Attributes map[string]any `json:"attributes,omitempty"`
	CapturedAt time.Time      `json:"captured_at"`
}

// Outcome is the terminal state of a planned collection task.
type Outcome string

const (
	OutcomePlanned   Outcome = "planned"
	OutcomeRunning   Outcome = "running"
	OutcomeOK        Outcome = "ok"
	OutcomeEmpty     Outcome = "empty"  // valid: nothing there (NOT a failure)
	OutcomeDenied    Outcome = "denied" // permission gap (expected, mapped)
	OutcomeThrottled Outcome = "throttled"
	OutcomeError     Outcome = "error"
	OutcomeSkipped   Outcome = "skipped" // reason carries why (upstream_failed, not_opted_in, api_disabled)
)

// LedgerRow tracks one (scope × resource × operation) planned unit through its
// lifecycle. Rows are created BEFORE execution so gaps are impossible to hide.
type LedgerRow struct {
	TaskID       string    `json:"task_id"`
	Scope        Scope     `json:"scope"`
	ResourceType string    `json:"resource_type"`
	Operation    string    `json:"operation"`
	Status       Outcome   `json:"status"`
	Reason       string    `json:"reason,omitempty"`
	Count        int       `json:"count"` // items produced
	StartedAt    time.Time `json:"started_at,omitempty"`
	EndedAt      time.Time `json:"ended_at,omitempty"`
}

// VersionBlock is embedded in the bundle manifest so any consumer can reconcile
// the three-way fit: collector ⇄ catalog contract ⇄ engine.
type VersionBlock struct {
	CollectorVersion       string            `json:"collector_version"`
	CatalogContractVersion string            `json:"catalog_contract_version"`
	ComponentVersions      map[string]string `json:"component_versions,omitempty"`
	SupportedCatalog       string            `json:"supported_catalog"`
	BundleSchemaVersion    string            `json:"bundle_schema_version"`
	MinEngine              string            `json:"min_engine"`
}

// Manifest is the bundle's self-describing header (bundle/manifest.json).
type Manifest struct {
	Version     VersionBlock   `json:"version"`
	Provider    string         `json:"provider"`
	Account     string         `json:"account"`
	CallerARN   string         `json:"caller_arn,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	EndedAt     time.Time      `json:"ended_at"`
	Scopes      []Scope        `json:"scopes"`
	Summary     map[string]int `json:"summary"` // counts by outcome
	Excluded    []string       `json:"excluded,omitempty"`
	IntegrityOK bool           `json:"integrity_ok"`
}
