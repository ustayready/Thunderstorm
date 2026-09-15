// Package pipeline runs the full engine: build base graph -> evaluate effective
// permissions -> derive multi-hop chains. Extracted so the CLI and the golden
// tests exercise the exact same path.
package pipeline

import (
	"strings"
	"time"

	"thunderstorm/engine/internal/build"
	"thunderstorm/engine/internal/bundle"
	"thunderstorm/engine/internal/derive"
	"thunderstorm/engine/internal/evaluator"
	evaluatorazure "thunderstorm/engine/internal/evaluator_azure"
	evaluatorgcp "thunderstorm/engine/internal/evaluator_gcp"
	"thunderstorm/engine/internal/model"
)

// Stats reports what each stage produced.
type Stats struct {
	Nodes          int
	BaseEdges      int
	PermEdges      int
	DerivedEdges   int
	SyntheticNodes int
}

// Run executes the full pipeline over a loaded bundle.
func Run(b *bundle.Bundle, at time.Time) ([]model.Node, []model.Edge, Stats) {
	res := build.Build(b.Artifacts, b.Facts, at)
	g := res.Graph
	base := len(g.Edges)

	// Provider-specific effective-permission evaluation. GCP's binding+role+hierarchy
	// model needs its own evaluator (and synthesizes identity nodes for members not in
	// inventory — users/groups/allUsers/WIF); AWS uses the statement/principal model.
	// A merged multi-scope bundle can span providers, so run EACH provider's evaluator
	// over ITS OWN facts (partitioned by fact.Provider) and union the results.
	var permEdges []model.Edge
	for _, p := range providersToEvaluate(b) {
		facts := factsForProvider(b.Facts, p)
		switch p {
		case "gcp":
			pe, extra := evaluatorgcp.EvaluatePermissions(facts, g.Nodes, at)
			g.Nodes = append(g.Nodes, extra...)
			res.SyntheticNodes += len(extra)
			permEdges = append(permEdges, pe...)
		case "azure":
			pe, extra := evaluatorazure.EvaluatePermissions(facts, g.Nodes, at)
			g.Nodes = append(g.Nodes, extra...)
			res.SyntheticNodes += len(extra)
			permEdges = append(permEdges, pe...)
		default: // aws
			store := evaluator.NewStore(facts)
			permEdges = append(permEdges, evaluator.EvaluatePermissions(store, g.Nodes, at)...)
		}
	}
	g.Edges = append(g.Edges, permEdges...)

	// "You are here": ensure the collector's own caller identity is a node and flagged as
	// the foothold. A human ADC identity often reaches a project via an org/folder role or
	// group membership, so it holds NO project-scoped binding and would otherwise be absent
	// from the graph — leaving the operator with no anchor to trace from. Synthesize it when
	// missing (GCP), and flag it wherever it already resolves.
	res.SyntheticNodes += applyFootholds(b, &g.Nodes)

	nodeType := make(map[string]string, len(g.Nodes))
	for _, n := range g.Nodes {
		nodeType[n.NodeID] = n.NodeType
	}
	derivedEdges := derive.Derive(g.Edges, nodeType, at)
	g.Edges = append(g.Edges, derivedEdges...)

	return g.Nodes, g.Edges, Stats{
		Nodes: len(g.Nodes), BaseEdges: base, PermEdges: len(permEdges),
		DerivedEdges: len(derivedEdges), SyntheticNodes: res.SyntheticNodes,
	}
}

// applyFootholds flags (and, for GCP, synthesizes when absent) the collector's caller
// identity for every scope so the graph always carries an explicit "you are here" anchor.
// Returns the number of nodes it newly synthesized.
func applyFootholds(b *bundle.Bundle, nodes *[]model.Node) int {
	callers := b.Manifest.Scopes
	if len(callers) == 0 && b.Manifest.CallerARN != "" {
		callers = []model.ManifestScope{{Provider: b.Manifest.Provider,
			Account: b.Manifest.Account, CallerARN: b.Manifest.CallerARN}}
	}
	synthed := 0
	for _, sc := range callers {
		caller := strings.TrimSpace(sc.CallerARN)
		if caller == "" {
			continue
		}
		if i := findFoothold(*nodes, caller); i >= 0 {
			if (*nodes)[i].Attributes == nil {
				(*nodes)[i].Attributes = map[string]any{}
			}
			(*nodes)[i].Attributes["foothold"] = true
			(*nodes)[i].Attributes["collector_identity"] = true
			continue
		}
		if sc.Provider == "gcp" || strings.Contains(caller, "gserviceaccount.com") {
			if n := evaluatorgcp.FootholdNode(caller, sc.Account); n != nil {
				*nodes = append(*nodes, *n)
				synthed++
			}
		}
	}
	return synthed
}

// findFoothold returns the index of the node representing caller (exact native-id segment,
// exact ARN, or caller embedded in the ARN), or -1. Mirrors the viz foothold resolver.
func findFoothold(nodes []model.Node, caller string) int {
	for i, n := range nodes {
		seg := n.NodeID
		if k := strings.LastIndexByte(seg, '|'); k >= 0 {
			seg = seg[k+1:]
		}
		if seg == caller || n.ARN == caller || (n.ARN != "" && strings.Contains(n.ARN, caller)) {
			return i
		}
	}
	return -1
}

// providersToEvaluate returns the providers whose evaluator must run. A single-provider
// bundle uses its manifest provider; a merged multi-scope bundle ("multi" or unset)
// runs every provider present in the facts (aws/gcp/azure), so a mixed-cloud graph gets
// each cloud's effective-permission model.
func providersToEvaluate(b *bundle.Bundle) []string {
	switch b.Manifest.Provider {
	case "aws", "gcp", "azure":
		return []string{b.Manifest.Provider}
	}
	present := map[string]bool{}
	for _, f := range b.Facts {
		p := f.Provider
		if p == "" {
			p = "aws"
		}
		present[p] = true
	}
	if len(present) == 0 {
		return []string{"aws"}
	}
	out := make([]string, 0, len(present))
	for _, p := range []string{"aws", "gcp", "azure"} {
		if present[p] {
			out = append(out, p)
		}
	}
	return out
}

// factsForProvider returns the subset of facts belonging to provider p (facts with an
// empty provider default to aws for back-compat).
func factsForProvider(facts []model.Fact, p string) []model.Fact {
	out := make([]model.Fact, 0, len(facts))
	for _, f := range facts {
		fp := f.Provider
		if fp == "" {
			fp = "aws"
		}
		if fp == p {
			out = append(out, f)
		}
	}
	return out
}
