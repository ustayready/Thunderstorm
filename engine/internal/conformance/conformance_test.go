// Package conformance guards the "logic in Go, RAGE is the spec" decision: it asserts every edge
// type the engine EMITS exists in RAGE's vocab/edge-types.json, and every node type the capability
// table targets exists in RAGE's vocab/node-types.json. If someone adds a capability/derivation with
// a typo'd or non-taxonomy type, this fails. RAGE is the source of truth (Thunderstorm no longer
// keeps its own schema). Skips when no RAGE checkout is present (offline/CI without RAGE).
package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"thunderstorm/engine/internal/derive"
	"thunderstorm/engine/internal/evaluator"
)

// rageRoot returns a live RAGE checkout from $RAGE_ROOT, or "" if unset (the
// conformance test then skips — CI/offline relies on the embedded snapshot).
func rageRoot() string {
	return os.Getenv("RAGE_ROOT")
}

func rageKeys(t *testing.T, file, field string) map[string]bool {
	t.Helper()
	root := rageRoot()
	if root == "" {
		t.Skip("no RAGE checkout")
	}
	data, err := os.ReadFile(filepath.Join(root, "vocab", file))
	if err != nil {
		t.Skipf("RAGE vocab not present (%s): %v", file, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	out := map[string]bool{}
	raw, ok := top[field]
	if !ok {
		return out
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s.%s: %v", file, field, err)
	}
	for k := range m {
		out[k] = true
	}
	return out
}

func TestEmittedEdgeTypesExistInRAGE(t *testing.T) {
	valid := rageKeys(t, "edge-types.json", "edge_types")
	var emitted []string
	emitted = append(emitted, evaluator.EmittedEdgeTypes()...)
	emitted = append(emitted, derive.EmittedEdgeTypes()...)
	for _, et := range emitted {
		if !valid[et] {
			t.Errorf("engine emits edge type %q which is NOT in RAGE vocab/edge-types.json", et)
		}
	}
}

func TestCapabilityTargetNodeTypesExistInRAGE(t *testing.T) {
	nodes := rageKeys(t, "node-types.json", "node_types")
	classes := rageKeys(t, "node-types.json", "classes")
	for _, nt := range evaluator.TargetNodeTypes() {
		if !nodes[nt] && !classes[nt] {
			t.Errorf("capability targets node type %q which is NOT in RAGE vocab/node-types.json", nt)
		}
	}
}
