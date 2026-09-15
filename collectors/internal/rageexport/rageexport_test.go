package rageexport

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func nd(recs ...map[string]any) []byte {
	var out []byte
	for _, r := range recs {
		b, _ := json.Marshal(r)
		out = append(out, b...)
		out = append(out, '\n')
	}
	return out
}

// synthetic scan workdir: 2 nodes, an observed + a derived edge, 1 fact, 1 ledger op, exposures.
func writeWorkdir(t *testing.T) string {
	t.Helper()
	wd := t.TempDir()
	g := filepath.Join(wd, "graph")
	bf := filepath.Join(wd, "bundle", "full")
	for _, d := range []string{g, filepath.Join(bf, "facts"), filepath.Join(bf, "ledger"), filepath.Join(bf, "exposure")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	A := "gcp|p|gcp:iam:sa|A"
	B := "gcp|p|gcp:storage:bucket|B"
	write := func(p string, b []byte) {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(g, "nodes.ndjson"), nd(
		map[string]any{"node_id": A, "node_type": "ServiceAccount", "provider": "gcp"},
		map[string]any{"node_id": B, "node_type": "ObjectStorage", "provider": "gcp"}))
	write(filepath.Join(g, "edges.ndjson"), nd(
		map[string]any{"edge_id": "e1", "type": "CanReadData", "source": A, "target": B, "nature": "explicit", "state": "ACTIVE", "relationship_kind": "DATA_ACCESS"},
		map[string]any{"edge_id": "e2", "type": "CanEscalateTo", "source": A, "target": B, "nature": "derived", "state": "ACTIVE", "rule_id": "r1", "relationship_kind": "DERIVED_ATTACK_PATH"}))
	write(filepath.Join(g, "paths.ndjson"), nil)
	// graph manifest (engine) carries no caller_arn; the bundle manifest (collector) does.
	write(filepath.Join(g, "manifest.json"), mustJSON(map[string]any{"provider": "gcp", "created_at": "2026-01-01T00:00:00Z"}))
	write(filepath.Join(bf, "manifest.json"), mustJSON(map[string]any{"provider": "gcp", "account": "p", "caller_arn": "A", "created_at": "2026-01-01T00:00:00Z"}))
	// fact refers to resources by native id (A, B) — the exporter must resolve to node_ids.
	write(filepath.Join(bf, "facts", "role_assignment.ndjson"), nd(
		map[string]any{"kind": "role_assignment", "source": "A", "target": "B", "edge_hint": "CanReadData", "provider": "gcp", "scope": map[string]any{"account": "p"}}))
	write(filepath.Join(bf, "ledger", "coverage.ndjson"), nd(
		map[string]any{"task_id": "t1", "operation": "gcp:iam:getIamPolicy", "status": "ok", "ended_at": "2026-01-01T00:00:00Z", "resource_type": "gcp:authorization:role-assignments", "scope": map[string]any{"account": "p"}}))
	write(filepath.Join(bf, "exposure", "hits.ndjson"), nd(
		map[string]any{"site_id": "s1", "resource_id": "B", "severity": "critical", "location": "iamPolicy"}))
	write(filepath.Join(bf, "exposure", "surfaces.ndjson"), nd(
		map[string]any{"site_id": "s2", "resource_id": "B", "severity": "high"}))
	return wd
}

func mustJSON(m map[string]any) []byte { b, _ := json.Marshal(m); return b }

func recordsOf(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return parseNDJSON(b)
}

func TestWorkdir_FullRAGE(t *testing.T) {
	wd := writeWorkdir(t)
	out := filepath.Join(t.TempDir(), "g.rage.ndjson")
	st, err := RunWorkdir(wd, out)
	if err != nil {
		t.Fatal(err)
	}
	if !st.RealEvidence {
		t.Error("workdir path should report real evidence")
	}
	recs := recordsOf(t, out)
	if recs[0]["kind"] != "manifest" {
		t.Fatalf("line 1 must be manifest, got %v", recs[0]["kind"])
	}
	// scope.foothold must be the collecting identity resolved to its node_id (merged
	// from the bundle manifest's caller_arn "A" -> node_id A).
	scope, _ := recs[0]["scope"].(map[string]any)
	if got := str(scope["foothold"]); got != "gcp|p|gcp:iam:sa|A" {
		t.Errorf("manifest scope.foothold = %q, want the caller's node_id", got)
	}
	kinds := map[string]int{}
	byID := map[string]map[string]any{}
	for _, r := range recs {
		kinds[str(r["kind"])]++
		if r["kind"] == "evidence" {
			byID[str(r["evidence_id"])] = r
		}
	}
	for k, want := range map[string]int{"node": 2, "edge": 2, "fact": 1, "finding": 1, "surface": 1} {
		if kinds[k] != want {
			t.Errorf("%s: got %d want %d", k, kinds[k], want)
		}
	}
	if kinds["evidence"] < 1 {
		t.Error("expected at least one evidence record")
	}
	// fact linked to the ledger evidence (normType role_assignment ~ role-assignments)
	var fact, observed, derived map[string]any
	for _, r := range recs {
		switch {
		case r["kind"] == "fact":
			fact = r
		case r["kind"] == "edge" && r["type"] == "CanReadData":
			observed = r
		case r["kind"] == "edge" && r["type"] == "CanEscalateTo":
			derived = r
		}
	}
	if fact["evidence"] == nil {
		t.Error("fact should link to ledger evidence")
	}
	// observed edge linked to the fact (fact refs resolved to node_ids and matched)
	if observed["facts"] == nil {
		t.Error("observed edge should link to the fact that justifies it")
	}
	// derived edge must carry evidence (synthesized fallback since no fact matched)
	if derived["evidence"] == nil {
		t.Error("derived edge must carry evidence")
	}
}

func TestZipOutput(t *testing.T) {
	wd := writeWorkdir(t)
	out := filepath.Join(t.TempDir(), "g.rage.zip")
	if _, err := RunWorkdir(wd, out); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	found := false
	for _, f := range zr.File {
		if f.Name == "graph.rage.ndjson" {
			found = true
		}
	}
	if !found {
		t.Error("zip output must contain graph.rage.ndjson")
	}
}
