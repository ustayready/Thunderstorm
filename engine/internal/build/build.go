// Package build turns an Evidence Bundle into the base graph: nodes from
// inventory, and the "direct" edges that need no permission evaluation
// (CanAssume, CrossAccountTrust, CanReachPort/PeeredWith/RoutesTo, MemberOf,
// HasPolicy, ExecutesAs). Permission-derived edges are added later (M4c).
package build

import (
	"fmt"
	"strings"
	"time"

	"thunderstorm/engine/internal/model"
	"thunderstorm/engine/internal/policy"
)

// Graph is the built base graph plus an index for edge/node lookups.
type Graph struct {
	Nodes   []model.Node
	Edges   []model.Edge
	byID    map[string]*model.Node
	byARN   map[string]string // arn -> node_id
	arnSeen map[string]bool
}

// Result carries build stats for the report.
type Result struct {
	Graph          *Graph
	SyntheticNodes int // nodes created for edge endpoints not present in inventory
	SkippedEdges   int
}

// nodeID derives a stable id for an inventory artifact.
func nodeID(provider, account, resourceType, nativeID string) string {
	return strings.Join([]string{provider, account, resourceType, nativeID}, "|")
}

// Build constructs the base graph from bundle artifacts + facts.
func Build(artifacts []model.Artifact, facts []model.Fact, at time.Time) *Result {
	g := &Graph{
		byID:    map[string]*model.Node{},
		byARN:   map[string]string{},
		arnSeen: map[string]bool{},
	}
	res := &Result{Graph: g}

	// --- Nodes from inventory ---
	for _, a := range artifacts {
		id := nodeID(a.Provider, a.Account, a.ResourceType, a.NativeID)
		n := model.Node{
			NodeID:     id,
			NodeType:   a.NodeType,
			Provider:   a.Provider,
			Account:    a.Account,
			ARN:        a.ARN,
			Scope:      a.Scope,
			Attributes: a.Attributes,
		}
		g.addNode(n)
		if a.ARN != "" {
			g.byARN[a.ARN] = id
		}
	}

	// --- Direct edges from facts ---
	for _, f := range facts {
		switch f.Kind {
		case "trust_policy":
			g.fromTrustPolicy(f, res, at)
		case "resource_policy":
			g.fromResourcePolicy(f, res, at)
		case "network_rule":
			g.directFact(f, relKindNetwork(f.EdgeHint), at)
		case "membership":
			g.directFact(f, "STRUCTURAL", at)
		case "identity_policy", "managed_policy", "scp",
			"iam_binding", "role_permissions", "hierarchy", "deny_policy",
			"role_assignment", "role_definition", "deny_assignment", "principal", "member_of",
			"entra_role_assignment", "entra_app_role", "entra_owner", "entra_group_owner",
			"entra_role_eligible", "mg_hierarchy", "public_container":
			// Consumed by the evaluator (AWS M4c / GCP M5e / Azure M6e), not a direct edge here.
			res.SkippedEdges++
		default:
			// Unknown fact kind with a usable hint + endpoints -> best-effort edge.
			if f.EdgeHint != "" && f.Source != "" && f.Target != "" {
				g.directFact(f, "AUTHORIZATION", at)
			} else {
				res.SkippedEdges++
			}
		}
	}

	// ExecutesAs from inventory role attributes.
	for _, a := range artifacts {
		role := roleFromAttrs(a.Attributes)
		if role == "" {
			continue
		}
		src := nodeID(a.Provider, a.Account, a.ResourceType, a.NativeID)
		tgt := g.ensureARNNode(role, "Role", a.Provider, at, res)
		g.addEdge(model.Edge{
			Type: "ExecutesAs", Source: src, Target: tgt,
			RelationshipKind: "EXECUTION", Nature: model.NatureExplicit,
			Provider: a.Provider, State: model.StateActive, Confidence: 1.0, Weight: 1.0,
			Narrative: nodeShort(src) + " executes as " + nodeShort(tgt),
			FirstSeen: at,
		})
	}

	return res
}

func (g *Graph) fromTrustPolicy(f model.Fact, res *Result, at time.Time) {
	// source = the role; principals in the doc can assume it -> CanAssume(principal -> role).
	roleNode := g.ensureARNNode(f.Source, "Role", f.Provider, at, res)
	doc := attrString(f.Attributes, "document")
	if doc == "" {
		return
	}
	pd, err := policy.Parse(doc)
	if err != nil {
		res.SkippedEdges++
		return
	}
	for _, st := range pd.Statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		for _, pr := range st.Principal.AWSPrincipals() {
			src := g.ensureARNNode(pr, "Identity", f.Provider, at, res)
			g.addEdge(model.Edge{
				Type: "CanAssume", Source: src, Target: roleNode,
				RelationshipKind: "AUTHORIZATION", Nature: model.NatureExplicit,
				Provider: f.Provider, State: model.StateActive, Confidence: 1.0, Weight: 1.0,
				Scope:     f.Source,
				Facts:     []string{model.FactID(f)},
				Evidence:  map[string]any{"trust_policy": true},
				Narrative: nodeShort(src) + " can assume " + nodeShort(roleNode),
				FirstSeen: at,
			})
		}
		// Service principals -> a service can assume (records the trust surface).
		for _, svc := range st.Principal.ByType["Service"] {
			src := g.ensureNamedNode("service:"+svc, "Service", f.Provider, f.Scope.Account, at, res)
			g.addEdge(model.Edge{
				Type: "CanAssume", Source: src, Target: roleNode,
				RelationshipKind: "AUTHORIZATION", Nature: model.NatureExplicit,
				Provider: f.Provider, State: model.StateActive, Confidence: 0.9, Weight: 2.0,
				Scope: f.Source, Facts: []string{model.FactID(f)}, Evidence: map[string]any{"service_trust": svc},
				Narrative: svc + " can assume " + nodeShort(roleNode),
				FirstSeen: at,
			})
		}
	}
}

func (g *Graph) fromResourcePolicy(f model.Fact, res *Result, at time.Time) {
	// source = the resource; external principals with an Allow -> CrossAccountTrust.
	resNode := g.ensureARNNode(f.Source, "Resource", f.Provider, at, res)
	resAccount := policy.AccountOf(f.Source)
	doc := attrString(f.Attributes, "policy")
	if doc == "" {
		doc = attrString(f.Attributes, "document")
	}
	if doc == "" {
		return
	}
	pd, err := policy.Parse(doc)
	if err != nil {
		res.SkippedEdges++
		return
	}
	for _, st := range pd.Statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if st.Principal.IsPublic() {
			// A "*" principal is only truly public if no condition confines it. A
			// same-account confinement (aws:SourceOwner/SourceAccount/PrincipalAccount
			// == this resource's account) means it is NOT public or cross-account at
			// all (e.g. the default SES SNS bounce/complaint topic policy) — skip it.
			// Any other condition scopes it -> CONDITIONAL rather than wide-open ACTIVE.
			if sameAccountConfined(st.Condition, resAccount) {
				continue
			}
			state := model.StateActive
			narrative := nodeShort(resNode) + " grants access to Everyone (public)"
			if len(st.Condition) > 0 {
				state = model.StateConditional
				narrative = nodeShort(resNode) + " grants access to * (scoped by a condition)"
			}
			pub := g.ensureNamedNode("principal:*", "Everyone", f.Provider, "", at, res)
			g.addEdge(model.Edge{
				Type: "CrossAccountTrust", Source: resNode, Target: pub,
				RelationshipKind: "AUTHORIZATION", Nature: model.NatureExplicit,
				Provider: f.Provider, State: state, Confidence: 1.0, Weight: 1.0,
				Scope: f.Source, Permissions: st.Action, Conditions: condLabelsOf(st.Condition),
				Facts:     []string{model.FactID(f)},
				Evidence:  map[string]any{"public": state == model.StateActive, "sid": st.SID},
				Narrative: narrative,
				FirstSeen: at,
			})
			continue
		}
		for _, pr := range st.Principal.AWSPrincipals() {
			prAccount := policy.AccountOf(pr)
			if prAccount != "" && resAccount != "" && prAccount == resAccount {
				continue // same-account grant is not cross-account trust
			}
			ext := g.ensureARNNode(pr, "Identity", f.Provider, at, res)
			g.addEdge(model.Edge{
				Type: "CrossAccountTrust", Source: resNode, Target: ext,
				RelationshipKind: "AUTHORIZATION", Nature: model.NatureExplicit,
				Provider: f.Provider, State: model.StateActive, Confidence: 1.0, Weight: 1.0,
				Scope: f.Source, Permissions: st.Action,
				Facts:     []string{model.FactID(f)},
				Evidence:  map[string]any{"external_account": prAccount, "sid": st.SID},
				Narrative: nodeShort(resNode) + " grants cross-account access to " + nodeShort(ext),
				FirstSeen: at,
			})
		}
	}
}

// sameAccountConfined reports whether a "*"-principal grant is restricted to the
// resource's own account by a StringEquals condition on a caller-account key
// (aws:SourceOwner / aws:SourceAccount / aws:PrincipalAccount / kms:CallerAccount /
// s3:ResourceAccount == resourceAccount). Such a grant is not public/cross-account.
func sameAccountConfined(cond policy.Condition, resourceAccount string) bool {
	if resourceAccount == "" {
		return false
	}
	acctKeys := map[string]bool{
		"aws:sourceowner": true, "aws:sourceaccount": true, "aws:principalaccount": true,
		"kms:calleraccount": true, "s3:resourceaccount": true,
	}
	for op, kv := range cond {
		if !strings.Contains(strings.ToLower(op), "stringequals") {
			continue
		}
		for k, vals := range kv {
			if !acctKeys[strings.ToLower(k)] {
				continue
			}
			for _, v := range vals {
				if v == resourceAccount {
					return true
				}
			}
		}
	}
	return false
}

// condLabelsOf renders a condition block as "Operator:key" labels for evidence.
func condLabelsOf(cond policy.Condition) []string {
	var out []string
	for op, kv := range cond {
		for k := range kv {
			out = append(out, op+":"+k)
		}
	}
	return out
}

// directFact emits an edge straight from a fact's source/target/hint.
func (g *Graph) directFact(f model.Fact, relKind string, at time.Time) {
	if f.Source == "" || f.Target == "" || f.EdgeHint == "" {
		return
	}
	src := g.ensureEndpoint(f.Source, f.Provider, at)
	tgt := g.ensureEndpoint(f.Target, f.Provider, at)
	weight := 1.0
	conf := 1.0
	perms := factPerms(f)
	g.addEdge(model.Edge{
		Type: f.EdgeHint, Source: src, Target: tgt,
		RelationshipKind: relKind, Nature: model.NatureExplicit,
		Provider: f.Provider, State: model.StateActive, Confidence: conf, Weight: weight,
		Scope: f.Scope.Region, Permissions: perms,
		Facts:     []string{model.FactID(f)}, // provenance: the fact this edge came from
		Narrative: nodeShort(src) + " " + f.EdgeHint + " " + nodeShort(tgt),
		FirstSeen: at,
	})
}

// ---------------------------------------------------------------------------
// node/edge helpers
// ---------------------------------------------------------------------------

func (g *Graph) addNode(n model.Node) {
	if _, ok := g.byID[n.NodeID]; ok {
		return
	}
	g.Nodes = append(g.Nodes, n)
	g.byID[n.NodeID] = &g.Nodes[len(g.Nodes)-1]
}

func (g *Graph) addEdge(e model.Edge) {
	e.EdgeID = model.EdgeID(e.Type, e.Source, e.Target, e.Scope)
	g.Edges = append(g.Edges, e)
}

// ensureEndpoint maps a fact endpoint (arn, cidr, id) to a node id, creating a
// synthetic node if it isn't in inventory.
func (g *Graph) ensureEndpoint(v, provider string, at time.Time) string {
	if strings.HasPrefix(v, "arn:") {
		if id, ok := g.byARN[v]; ok {
			return id
		}
		return g.ensureARNNodeRaw(v, "Resource", provider, at)
	}
	if id, ok := g.byID[v]; ok {
		return id.NodeID
	}
	// cidr / group-id / bare id
	return g.ensureNamedNodeRaw(v, endpointType(v), provider, at)
}

func (g *Graph) ensureARNNode(arn, fallbackType, provider string, at time.Time, res *Result) string {
	if id, ok := g.byARN[arn]; ok {
		return id
	}
	res.SyntheticNodes++
	return g.ensureARNNodeRaw(arn, fallbackType, provider, at)
}

func (g *Graph) ensureARNNodeRaw(arn, fallbackType, provider string, at time.Time) string {
	id := "arn|" + arn
	if _, ok := g.byID[id]; ok {
		return id
	}
	g.addNode(model.Node{
		NodeID: id, NodeType: fallbackType, Provider: provider,
		Account: policy.AccountOf(arn), ARN: arn,
		Attributes: map[string]any{"synthetic": true},
	})
	g.byARN[arn] = id
	return id
}

func (g *Graph) ensureNamedNode(name, typ, provider, account string, at time.Time, res *Result) string {
	id := "name|" + name
	if _, ok := g.byID[id]; ok {
		return id
	}
	res.SyntheticNodes++
	g.addNode(model.Node{
		NodeID: id, NodeType: typ, Provider: provider, Account: account,
		Attributes: map[string]any{"synthetic": true, "name": name},
	})
	return id
}

func (g *Graph) ensureNamedNodeRaw(name, typ, provider string, at time.Time) string {
	id := "name|" + name
	if _, ok := g.byID[id]; ok {
		return id
	}
	g.addNode(model.Node{
		NodeID: id, NodeType: typ, Provider: provider,
		Attributes: map[string]any{"synthetic": true, "name": name},
	})
	return id
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func relKindNetwork(hint string) string { return "NETWORK" }

func endpointType(v string) string {
	switch {
	case strings.Contains(v, "/"): // cidr
		return "CIDR"
	case strings.HasPrefix(v, "sg-"):
		return "SecurityGroup"
	case strings.HasPrefix(v, "vpc-"):
		return "VirtualNetwork"
	default:
		return "Unknown"
	}
}

func roleFromAttrs(attrs map[string]any) string {
	for _, k := range []string{"role_arn", "Configuration.Role", "role", "execution_role"} {
		if s, ok := attrs[k].(string); ok && strings.HasPrefix(s, "arn:") {
			return s
		}
	}
	return ""
}

func factPerms(f model.Fact) []string {
	if v, ok := f.Attributes["port"]; ok {
		return []string{fmt.Sprintf("port:%v", v)}
	}
	return nil
}

func attrString(attrs map[string]any, key string) string {
	if attrs == nil {
		return ""
	}
	if s, ok := attrs[key].(string); ok {
		return s
	}
	return ""
}

// nodeShort renders a compact label for narratives (last ARN segment or name).
func nodeShort(nodeID string) string {
	s := nodeID
	if i := strings.LastIndex(s, "|"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.HasPrefix(s, "service") {
		s = s[i+1:]
	}
	return s
}
