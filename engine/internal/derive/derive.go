// Package derive composes explicit edges into multi-hop attack-path edges,
// following rules/derived/* (implemented in Go).
// It runs a fixpoint so chains collapse:
//
//	attacker -CanModifyCode-> fn -ExecutesAs-> role -CanReadSecret-> secret
//	  =>  attacker -CanReadSecret-> secret   (and -CanExecuteAs-> role)
//
// Rules join two edges by one of three shapes, plus single-edge promotions.
// State propagates weakest-contributor (RULE-FORMAT.md).
package derive

import (
	"sort"
	"strings"
	"time"

	"thunderstorm/engine/internal/model"
)

// capabilityTypes propagate through a "become / act-as / control" pivot: if you
// can become ?b or control the compute ?b, you inherit ?b's capability over ?c.
var capabilityTypes = map[string]bool{
	"CanReadSecret": true, "CanReadData": true, "CanWriteData": true,
	"CanInvoke": true, "CanModifyCode": true, "CanModifyConfiguration": true,
	"CanExecuteCommand": true, "CanDecrypt": true, "CanExportKey": true,
	"CanPassIdentity": true, "CanTrigger": true, "CanModifyPolicy": true,
	"CanModify": true, "CanModifyTrust": true, "CanAddMember": true,
	"CanCreateCredentialFor": true, "CanResetCredential": true,
	"CanDelete": true, "CanStart": true,
	// GCP: impersonation/signing are themselves inheritable, so SA->SA->SA chains
	// (getAccessToken / signJwt) compose to multi-hop escalation.
	"CanImpersonate": true, "CanSignAs": true, "CanGrantPermission": true,
}

// controlPivots: controlling/invoking a compute inherits what the compute can do.
var controlPivots = map[string]bool{
	"CanModifyCode": true, "CanExecuteCommand": true,
	"CanInvoke": true, "CanModifyConfiguration": true,
}

// JoinKind selects how two edges are joined.
type JoinKind int

const (
	// JoinChain: e1.Target == e2.Source  =>  emit(e1.Source -> e2.Target).
	JoinChain JoinKind = iota
	// JoinSameSource: e1.Source == e2.Source  =>  emit(e1.Source -> e2.Target).
	JoinSameSource
	// JoinSameTarget: e1.Target == e2.Target  =>  emit(e1.Source -> e2.Source).
	JoinSameTarget
)

// Rule is a two-edge join.
type Rule struct {
	ID         string
	Join       JoinKind
	First      map[string]bool // first-clause edge types
	Second     map[string]bool // second-clause types; nil => capabilityTypes
	EmitSame   bool            // emit type = second clause's type (capability inheritance)
	EmitType   string          // used when !EmitSame
	Prior      float64
	BaseWeight float64
}

// Promotion is a single-edge rule: an edge of a Match type is added as a new edge
// (optionally requiring an identity target, or a specific target node-class set).
type Promotion struct {
	ID          string
	Match       map[string]bool
	Emit        string
	RelKind     string
	OnlyToIDs   bool
	OnlyToTypes map[string]bool // nil => any target type
	Prior       float64
}

// accountContainerTypes are the "own this container = own every resource in the same
// account" nodes (account-wide fan-out): GCP Project, Azure Subscription, AWS Account.
// Azure ManagementGroup + ResourceGroup takeover is SCOPE-aware (a MG covers only its
// descendant subs, an RG only its own resources) and handled in evaluator_azure, not here.
var accountContainerTypes = map[string]bool{
	"Project": true, "Subscription": true, "Account": true,
}

var identityNodeTypes = map[string]bool{
	"HumanIdentity": true, "Role": true, "Group": true, "ServiceIdentity": true,
	"FederatedIdentity": true, "ApplicationIdentity": true, "WorkloadIdentity": true,
	"ServiceAccount": true, // GCP SA — impersonation targets it (promotes to CanEscalateTo)
}

var rules = []Rule{
	// --- capability inheritance (become/control -> inherit target's caps) ---
	{ID: "inherit-via-assume", Join: JoinChain, First: set("CanAssume"), EmitSame: true, Prior: 0.95, BaseWeight: 1.0},
	// GCP: impersonating a service account inherits everything IT can do (the
	// getAccessToken/signJwt privesc backbone) — the analog of AWS assume-role.
	{ID: "inherit-via-impersonate", Join: JoinChain, First: set("CanImpersonate"), EmitSame: true, Prior: 0.9, BaseWeight: 1.0},
	{ID: "inherit-via-execute", Join: JoinChain, First: set("ExecutesAs"), EmitSame: true, Prior: 0.9, BaseWeight: 1.0},
	{ID: "inherit-via-compute-control", Join: JoinChain, First: controlPivots, EmitSame: true, Prior: 0.85, BaseWeight: 1.5},

	// --- CanExecuteAs (execution pivot) ---
	{ID: "execute-as-via-compute-control", Join: JoinChain, First: controlPivots, Second: set("ExecutesAs"),
		EmitType: "CanExecuteAs", Prior: 0.85, BaseWeight: 1.5},
	{ID: "execute-as-via-assume", Join: JoinChain, First: set("CanAssume"), Second: set("ExecutesAs"),
		EmitType: "CanExecuteAs", Prior: 0.9, BaseWeight: 1.0},
	{ID: "execute-as-via-trigger", Join: JoinChain, First: set("CanTrigger"), Second: set("ExecutesAs"),
		EmitType: "CanExecuteAs", Prior: 0.8, BaseWeight: 2.0}, // cicd + messaging trigger-executes-as
	{ID: "execute-as-via-config-identity-swap", Join: JoinSameSource, First: set("CanModifyConfiguration"),
		Second: set("CanPassIdentity"), EmitType: "CanExecuteAs", Prior: 0.8, BaseWeight: 2.0},
	{ID: "execute-as-via-schedule", Join: JoinSameSource, First: set("CanSchedule"),
		Second: set("CanPassIdentity"), EmitType: "CanExecuteAs", Prior: 0.8, BaseWeight: 2.0},

	// --- credential -> impersonation ---
	{ID: "read-secret-yields-identity", Join: JoinChain, First: set("CanReadSecret", "CanReadCredential"),
		Second: set("CredentialsFor", "CredentialValidFor"), EmitType: "CanImpersonate", Prior: 0.9, BaseWeight: 1.0},

	// --- messaging / cicd trigger chains ---
	{ID: "write-then-trigger", Join: JoinChain, First: set("CanWriteData"), Second: set("CanTrigger"),
		EmitType: "CanTrigger", Prior: 0.85, BaseWeight: 1.5},
	{ID: "trigger-orchestrates-trigger", Join: JoinChain, First: set("CanTrigger"), Second: set("CanTrigger"),
		EmitType: "CanTrigger", Prior: 0.85, BaseWeight: 1.5},

	// --- container image supply chain (poison an image consumers reference) ---
	{ID: "image-push-poisons-consumers", Join: JoinSameTarget, First: set("CanModifyCode"),
		Second: set("ContainsResourceReference"), EmitType: "CanModifyCode", Prior: 0.8, BaseWeight: 2.0},

	// --- hierarchy (control a parent -> control its children) ---
	{ID: "control-inherits-contains", Join: JoinChain, First: set("Controls"), Second: set("Contains"),
		EmitType: "Controls", Prior: 0.9, BaseWeight: 1.0},

	// --- network reachability chaining (proxy/LB hop) ---
	{ID: "network-proxy-reach", Join: JoinChain, First: set("CanNetworkReach"), Second: set("CanNetworkReach"),
		EmitType: "CanNetworkReach", Prior: 0.85, BaseWeight: 1.0},
}

var promotions = []Promotion{
	// escalation: controlling an identity's creds/policy/trust/group/grant.
	{ID: "control-identity-is-escalation",
		Match: set("CanCreateCredentialFor", "CanResetCredential", "CanModifyTrust", "CanAddMember", "CanModifyPolicy", "CanGrantPermission"),
		Emit:  "CanEscalateTo", RelKind: "DERIVED_ATTACK_PATH", OnlyToIDs: true, Prior: 0.9},
	{ID: "impersonate-is-escalation", Match: set("CanImpersonate", "CanExecuteAs", "CanFederateAs"),
		Emit: "CanEscalateTo", RelKind: "DERIVED_ATTACK_PATH", OnlyToIDs: true, Prior: 0.9},

	// control: rewriting policy/trust or deleting/owning a resource, or granting perms.
	{ID: "modify-is-control", Match: set("CanModifyPolicy", "CanModifyTrust", "CanModify", "CanDelete", "CanTakeOwnership", "CanGrantPermission"),
		Emit: "CanControl", RelKind: "CONTROL", Prior: 0.85},

	// control-implies-read: if you control a resource you can rewrite its IAM policy to
	// grant yourself read — so controlling a secret/store yields the data in it.
	{ID: "control-secret-reads-it", Match: set("CanControl"), Emit: "CanReadSecret",
		RelKind: "CREDENTIAL", OnlyToTypes: set("Secret"), Prior: 0.8},
	{ID: "control-store-reads-it", Match: set("CanControl"), Emit: "CanReadData",
		RelKind: "DATA_ACCESS", OnlyToTypes: set("ObjectStorage", "DataWarehouse", "FileStore", "BlockStorage", "Cache", "NoSQLDatabase", "RelationalDatabase"), Prior: 0.8},

	// federation: an external identity mapping / federation confers impersonation + entry.
	{ID: "mapsto-federates", Match: set("ExternalIdentityMapsTo"), Emit: "CanFederateAs",
		RelKind: "AUTHORIZATION", OnlyToIDs: true, Prior: 0.9},
	{ID: "federate-enter-account", Match: set("CanFederateAs"), Emit: "CanEnterAccount",
		RelKind: "DERIVED_ATTACK_PATH", OnlyToIDs: true, Prior: 0.85},
	{ID: "federate-impersonate", Match: set("CanFederateAs"), Emit: "CanImpersonate",
		RelKind: "AUTHORIZATION", OnlyToIDs: true, Prior: 0.85},

	// network: a private-link or internet exposure is network reachability.
	{ID: "private-reach", Match: set("PrivateReachability"), Emit: "CanNetworkReach", RelKind: "NETWORK", Prior: 0.9},
	{ID: "internet-reach", Match: set("ExposedToInternet"), Emit: "CanNetworkReach", RelKind: "NETWORK", Prior: 0.85},
}

// Derive runs the rules to a fixpoint and returns the newly-derived edges.
// nodeType maps node_id -> node_type so promotions can require an identity target.
func Derive(edges []model.Edge, nodeType map[string]string, at time.Time) []model.Edge {
	type key struct{ t, s, d, sc string }
	present := map[key]model.Edge{}
	for _, e := range edges {
		present[key{e.Type, e.Source, e.Target, e.Scope}] = e
	}

	var derived []model.Edge
	upsert := func(ne model.Edge) bool {
		k := key{ne.Type, ne.Source, ne.Target, ne.Scope}
		if ex, ok := present[k]; ok {
			if betterEdge(ne, ex) {
				present[k] = ne
				replaceDerived(&derived, ne)
				return true
			}
			return false
		}
		present[k] = ne
		derived = append(derived, ne)
		return true
	}

	changed := true
	for changed {
		changed = false
		all := make([]model.Edge, 0, len(present))
		bySource := map[string][]model.Edge{}
		byTarget := map[string][]model.Edge{}
		for _, e := range present {
			all = append(all, e)
			bySource[e.Source] = append(bySource[e.Source], e)
			byTarget[e.Target] = append(byTarget[e.Target], e)
		}

		for _, r := range rules {
			for _, e1 := range all {
				if !r.First[e1.Type] {
					continue
				}
				var partners []model.Edge
				switch r.Join {
				case JoinChain:
					partners = bySource[e1.Target]
				case JoinSameSource:
					partners = bySource[e1.Source]
				case JoinSameTarget:
					partners = byTarget[e1.Target]
				}
				for _, e2 := range partners {
					if e2.EdgeID == e1.EdgeID || !ruleAllowsSecond(r, e2.Type) {
						continue
					}
					if upsert(composeEdge(r, e1, e2, at)) {
						changed = true
					}
				}
			}
		}
		for _, p := range promotions {
			for _, e := range all {
				if !p.Match[e.Type] {
					continue
				}
				if p.OnlyToIDs && !identityNodeTypes[nodeType[e.Target]] {
					continue
				}
				if p.OnlyToTypes != nil && !p.OnlyToTypes[nodeType[e.Target]] {
					continue
				}
				if upsert(promote(p, e, at)) {
					changed = true
				}
			}
		}

		// project takeover: whoever can rewrite a project's IAM policy can self-grant
		// any role -> owns every resource in that project (read every secret, control
		// every SA). Fan CanControl out to each resource in the same account; SAs also
		// become escalation targets. Google-managed source agents are already excluded
		// upstream (evaluator), so this only fires for attacker-controllable principals.
		for _, e := range all {
			if e.Type != "CanControl" && e.Type != "CanGrantPermission" {
				continue
			}
			if !accountContainerTypes[nodeType[e.Target]] {
				continue
			}
			acct := accountOf(e.Target)
			if acct == "" {
				continue
			}
			for tid, tt := range nodeType {
				if tid == e.Source || tt == "Project" || accountOf(tid) != acct {
					continue
				}
				if upsert(takeoverEdge(e, tid, "CanControl", "CONTROL", at)) {
					changed = true
				}
				if identityNodeTypes[tt] {
					if upsert(takeoverEdge(e, tid, "CanEscalateTo", "DERIVED_ATTACK_PATH", at)) {
						changed = true
					}
				}
			}
		}

		// tenant takeover: controlling the Entra Tenant (Global Admin / RoleManagement.
		// ReadWrite.Directory) owns every subscription under it (which then cascades to
		// their resources via subscription-takeover) and can become any identity.
		for _, e := range all {
			if e.Type != "CanControl" && e.Type != "CanGrantPermission" {
				continue
			}
			if nodeType[e.Target] != "Tenant" {
				continue
			}
			for tid, tt := range nodeType {
				if tid == e.Source {
					continue
				}
				if tt == "Subscription" {
					if upsert(takeoverEdge(e, tid, "CanControl", "CONTROL", at)) {
						changed = true
					}
				} else if identityNodeTypes[tt] {
					if upsert(takeoverEdge(e, tid, "CanEscalateTo", "DERIVED_ATTACK_PATH", at)) {
						changed = true
					}
				}
			}
		}
	}
	sort.Slice(derived, func(i, j int) bool { return derived[i].EdgeID < derived[j].EdgeID })
	return derived
}

// accountOf parses the account segment from a node id of the form
// provider|account|type|native.
func accountOf(nodeID string) string {
	parts := strings.Split(nodeID, "|")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// takeoverEdge builds a derived project-takeover edge from a CanControl/CanGrantPermission
// edge on a Project to a specific resource in that project.
func takeoverEdge(src model.Edge, target, emitType, relKind string, at time.Time) model.Edge {
	from := src.DerivedFrom
	if len(from) == 0 {
		from = []string{src.EdgeID}
	}
	ne := model.Edge{
		Type: emitType, Source: src.Source, Target: target,
		RelationshipKind: relKind, Nature: model.NatureDerived,
		Provider: src.Provider, State: src.State, Confidence: src.Confidence * 0.85,
		Weight: src.Weight + 2.0, DerivedFrom: from, RuleID: "project-takeover",
		Evidence:  map[string]any{"rule": "project-takeover", "pivot": src.Type},
		Narrative: src.Narrative + " -> owns the whole project",
		FirstSeen: at,
	}
	ne.EdgeID = model.EdgeID(ne.Type, ne.Source, ne.Target, ne.Scope)
	return ne
}

func ruleAllowsSecond(r Rule, t string) bool {
	if r.Second != nil {
		return r.Second[t]
	}
	return capabilityTypes[t]
}

func composeEdge(r Rule, e1, e2 model.Edge, at time.Time) model.Edge {
	emitType := e2.Type
	if !r.EmitSame {
		emitType = r.EmitType
	}
	// join geometry -> emitted endpoints
	src, tgt := e1.Source, e2.Target
	if r.Join == JoinSameTarget {
		tgt = e2.Source
	}
	ne := model.Edge{
		Type: emitType, Source: src, Target: tgt,
		RelationshipKind: e2.RelationshipKind, Nature: model.NatureDerived,
		Provider: e2.Provider, State: weakest(e1.State, e2.State),
		Confidence: min(e1.Confidence, e2.Confidence) * r.Prior,
		Weight:     e1.Weight + e2.Weight + r.BaseWeight, Scope: e2.Scope,
		Permissions: e2.Permissions, Conditions: unionConds(e1, e2),
		DerivedFrom: appendDerivedFrom(e1, e2), RuleID: r.ID,
		Evidence:  map[string]any{"rule": r.ID, "pivot": e1.Type},
		Narrative: e1.Narrative + " -> " + e2.Narrative,
		FirstSeen: at,
	}
	ne.EdgeID = model.EdgeID(ne.Type, ne.Source, ne.Target, ne.Scope)
	return ne
}

func promote(p Promotion, e model.Edge, at time.Time) model.Edge {
	from := e.DerivedFrom
	if len(from) == 0 {
		from = []string{e.EdgeID}
	}
	relKind := p.RelKind
	if relKind == "" {
		relKind = "DERIVED_ATTACK_PATH"
	}
	ne := model.Edge{
		Type: p.Emit, Source: e.Source, Target: e.Target,
		RelationshipKind: relKind, Nature: model.NatureDerived,
		Provider: e.Provider, State: e.State, Confidence: e.Confidence * p.Prior,
		Weight: e.Weight, Scope: e.Scope, Permissions: e.Permissions,
		Conditions: e.Conditions, DerivedFrom: from, RuleID: p.ID,
		Evidence:  map[string]any{"rule": p.ID, "from": e.Type},
		Narrative: e.Narrative + " (" + p.Emit + ")",
		FirstSeen: at,
	}
	ne.EdgeID = model.EdgeID(ne.Type, ne.Source, ne.Target, ne.Scope)
	return ne
}

func appendDerivedFrom(e1, e2 model.Edge) []string {
	var out []string
	if len(e1.DerivedFrom) > 0 {
		out = append(out, e1.DerivedFrom...)
	} else {
		out = append(out, e1.EdgeID)
	}
	if len(e2.DerivedFrom) > 0 {
		out = append(out, e2.DerivedFrom...)
	} else {
		out = append(out, e2.EdgeID)
	}
	return out
}

func weakest(a, b string) string {
	if a == model.StateBlocked || b == model.StateBlocked {
		return model.StateBlocked
	}
	if a == model.StateActive && b == model.StateActive {
		return model.StateActive
	}
	return model.StateConditional
}

func unionConds(e1, e2 model.Edge) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range append(append([]string{}, e1.Conditions...), e2.Conditions...) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func betterEdge(cand, existing model.Edge) bool {
	if cand.Nature != model.NatureDerived || existing.Nature != model.NatureDerived {
		return false // never overwrite an explicit edge
	}
	if cand.Weight != existing.Weight {
		return cand.Weight < existing.Weight
	}
	return stateRank(cand.State) > stateRank(existing.State)
}

func stateRank(s string) int {
	switch s {
	case model.StateActive:
		return 2
	case model.StateConditional:
		return 1
	default:
		return 0
	}
}

func replaceDerived(derived *[]model.Edge, ne model.Edge) {
	for i := range *derived {
		if (*derived)[i].EdgeID == ne.EdgeID {
			(*derived)[i] = ne
			return
		}
	}
	*derived = append(*derived, ne)
}

func set(types ...string) map[string]bool {
	m := make(map[string]bool, len(types))
	for _, t := range types {
		m[t] = true
	}
	return m
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// EmittedEdgeTypes returns the distinct edge types the derivation rules produce
// (fixed EmitType rules + promotions) for the conformance test.
func EmittedEdgeTypes() []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, r := range rules {
		if !r.EmitSame {
			add(r.EmitType)
		}
	}
	for _, p := range promotions {
		add(p.Emit)
	}
	return out
}
