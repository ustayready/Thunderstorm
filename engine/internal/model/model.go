// Package model defines the engine's graph types: Node, Edge, Path, and the
// bundle-side records it reads. The NDJSON Evidence Bundle is the contract, so
// these mirror the collector's on-disk JSON rather than importing its types.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// EdgeID derives a stable, unique id for an edge from its identity tuple. Every
// edge MUST have one — the graph index keys on it, so empty/colliding ids corrupt
// traversal.
func EdgeID(typ, source, target, scope string) string {
	h := sha256.Sum256([]byte(typ + "|" + source + "|" + target + "|" + scope))
	return "e_" + hex.EncodeToString(h[:8])
}

// Scope identifies WHERE a fact/resource lives. Mirrors the collector's Scope.
type Scope struct {
	Provider string `json:"provider"`
	Account  string `json:"account"`
	Region   string `json:"region,omitempty"`
	Global   bool   `json:"global,omitempty"`
}

// ---------------------------------------------------------------------------
// Bundle-side records (read from collectors/bundle/full/*). Field tags match
// the collector's model exactly so json.Unmarshal reads the real files.
// ---------------------------------------------------------------------------

// Artifact is one collected resource (inventory/*.ndjson) -> becomes a Node.
type Artifact struct {
	Provider     string            `json:"provider"`
	Account      string            `json:"account"`
	Scope        Scope             `json:"scope"`
	ResourceType string            `json:"resource_type"`
	NodeType     string            `json:"node_type,omitempty"`
	NativeID     string            `json:"native_id"`
	ARN          string            `json:"arn,omitempty"`
	Attributes   map[string]any    `json:"attributes,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	CollectedBy  []string          `json:"collected_by,omitempty"`
	CapturedAt   time.Time         `json:"captured_at"`
}

// Fact is a normalized relationship/policy/network fact (facts/*.ndjson). Its
// EdgeHint names the edge type it feeds.
type Fact struct {
	Kind       string         `json:"kind"`
	EdgeHint   string         `json:"edge_hint"`
	Provider   string         `json:"provider"`
	Scope      Scope          `json:"scope"`
	Source     string         `json:"source"`
	Target     string         `json:"target,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	CapturedAt time.Time      `json:"captured_at"`
}

// ExposureHit is a credential/secret surfaced by a probe (exposure/hits.ndjson).
type ExposureHit struct {
	SiteID     string `json:"site_id"`
	ResourceID string `json:"resource_id"`
	Provider   string `json:"provider"`
	Scope      Scope  `json:"scope"`
	EmitsHint  string `json:"emits_hint"`
	Severity   string `json:"severity"`
	Location   string `json:"location"`
	Found      bool   `json:"found"`
	ValueRef   string `json:"value_ref,omitempty"`
}

// VersionBlock / Manifest mirror the bundle header for the compatibility check.
type VersionBlock struct {
	CollectorVersion       string `json:"collector_version"`
	CatalogContractVersion string `json:"catalog_contract_version"`
	BundleSchemaVersion    string `json:"bundle_schema_version"`
	MinEngine              string `json:"min_engine"`
}

type Manifest struct {
	Version   VersionBlock    `json:"version"`
	Provider  string          `json:"provider"`
	Account   string          `json:"account"`
	CallerARN string          `json:"caller_arn,omitempty"`
	Scopes    []ManifestScope `json:"scopes,omitempty"`
}

// ManifestScope records one collection target in a merged multi-scope bundle. Its
// CallerARN is the identity the collector authenticated as for THAT scope — the seed
// for the "you are here" foothold node (which may hold no binding of its own).
type ManifestScope struct {
	Provider  string `json:"provider,omitempty"`
	Account   string `json:"account,omitempty"`
	CallerARN string `json:"caller_arn,omitempty"`
}

// ---------------------------------------------------------------------------
// Graph types (the engine's output — conform to RAGE vocab/edge-types.json).
// ---------------------------------------------------------------------------

// Node is a graph vertex. NodeID = provider|account|resource_type|native_id.
type Node struct {
	NodeID     string         `json:"node_id"`
	NodeType   string         `json:"node_type"`
	Provider   string         `json:"provider"`
	Account    string         `json:"account"`
	ARN        string         `json:"arn,omitempty"`
	Scope      Scope          `json:"scope"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Edge states (RAGE vocab/edge-types.json edge_states).
const (
	StateActive      = "ACTIVE"
	StateConditional = "CONDITIONAL"
	StatePotential   = "POTENTIAL"
	StateBlocked     = "BLOCKED"
	StateUnknown     = "UNKNOWN"
)

// Edge natures.
const (
	NatureExplicit = "explicit"
	NatureDerived  = "derived"
)

// Edge is a directed capability edge (RAGE vocab/edge-types.json edge_types).
type Edge struct {
	EdgeID           string         `json:"edge_id"`
	Type             string         `json:"type"`
	Source           string         `json:"source"`
	Target           string         `json:"target"`
	Category         string         `json:"category,omitempty"`
	RelationshipKind string         `json:"relationship_kind,omitempty"`
	Nature           string         `json:"nature"`
	Provider         string         `json:"provider"`
	State            string         `json:"state"`
	Confidence       float64        `json:"confidence"`
	Weight           float64        `json:"weight"`
	Scope            string         `json:"scope,omitempty"`
	Permissions      []string       `json:"permissions,omitempty"`
	Conditions       []string       `json:"conditions,omitempty"`
	DerivedFrom      []string       `json:"derived_from,omitempty"`
	Facts            []string       `json:"facts,omitempty"` // fact_ids that justify an observed edge (provenance)
	RuleID           string         `json:"rule_id,omitempty"`
	Evidence         map[string]any `json:"evidence,omitempty"`
	Narrative        string         `json:"narrative,omitempty"`
	FirstSeen        time.Time      `json:"first_seen"`
}

// FactID is the stable, deterministic id of a fact — a natural key over the observation's
// identity (NOT its volatile captured_at/attributes). The engine stamps it onto edges built
// from a fact; the RAGE exporter recomputes the identical id from the bundle facts, so edges
// and facts link up without sharing code across modules. Keep this algorithm in lockstep with
// collectors/internal/rageexport.factID.
func FactID(f Fact) string {
	key := f.Provider + "|" + f.Kind + "|" + f.Source + "|" + f.Target + "|" + f.EdgeHint +
		"|" + f.Scope.Account
	sum := sha256.Sum256([]byte(key))
	return "fact-" + hex.EncodeToString(sum[:])[:12]
}

// Path is a derived multi-hop attack path (paths.ndjson).
type Path struct {
	PathID    string   `json:"path_id"`
	Source    string   `json:"source"`
	Target    string   `json:"target"`
	EdgeIDs   []string `json:"edge_ids"`
	Score     float64  `json:"score"`
	Narrative string   `json:"narrative,omitempty"`
}
