// Package output writes the graph artifact: nodes/edges/paths NDJSON, a manifest,
// and a human report.md.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"thunderstorm/engine/internal/model"
)

// Manifest is the graph artifact header.
type Manifest struct {
	EngineVersion          string         `json:"engine_version"`
	SourceBundle           string         `json:"source_bundle"`
	CatalogContractVersion string         `json:"catalog_contract_version,omitempty"`
	Provider               string         `json:"provider,omitempty"`
	Account                string         `json:"account,omitempty"`
	BuiltAt                time.Time      `json:"built_at"`
	Counts                 map[string]int `json:"counts"`
}

// Write emits the full graph artifact under dir.
func Write(dir string, nodes []model.Node, edges []model.Edge, paths []model.Path, man Manifest) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(dir, "nodes.ndjson"), len(nodes), func(i int) any { return nodes[i] }); err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(dir, "edges.ndjson"), len(edges), func(i int) any { return edges[i] }); err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(dir, "paths.ndjson"), len(paths), func(i int) any { return paths[i] }); err != nil {
		return err
	}
	man.Counts = map[string]int{"nodes": len(nodes), "edges": len(edges), "paths": len(paths)}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), man); err != nil {
		return err
	}
	return writeReport(filepath.Join(dir, "report.md"), nodes, edges, paths, man)
}

func writeNDJSON(path string, n int, get func(int) any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := 0; i < n; i++ {
		if err := enc.Encode(get(i)); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeReport(path string, nodes []model.Node, edges []model.Edge, paths []model.Path, man Manifest) error {
	nodeByType := map[string]int{}
	for _, n := range nodes {
		t := n.NodeType
		if t == "" {
			t = "(untyped)"
		}
		nodeByType[t]++
	}
	edgeByType := map[string]int{}
	edgeByState := map[string]int{}
	for _, e := range edges {
		edgeByType[e.Type]++
		edgeByState[e.State]++
	}

	var b []byte
	add := func(format string, a ...any) { b = append(b, []byte(fmt.Sprintf(format, a...))...) }

	add("# Thunderstorm Graph Report\n\n")
	add("Engine `%s` — built %s from bundle `%s`.\n\n", man.EngineVersion, man.BuiltAt.Format(time.RFC3339), man.SourceBundle)
	add("- **Nodes:** %d\n- **Edges:** %d\n- **Paths:** %d\n\n", len(nodes), len(edges), len(paths))

	add("## Edges by type\n\n| type | count |\n|---|---|\n")
	for _, kv := range sortedCounts(edgeByType) {
		add("| %s | %d |\n", kv.k, kv.v)
	}
	add("\n## Edges by state\n\n| state | count |\n|---|---|\n")
	for _, kv := range sortedCounts(edgeByState) {
		add("| %s | %d |\n", kv.k, kv.v)
	}
	add("\n## Nodes by type\n\n| node_type | count |\n|---|---|\n")
	for _, kv := range sortedCounts(nodeByType) {
		add("| %s | %d |\n", kv.k, kv.v)
	}

	if n := edgeByState[model.StateConditional]; n > 0 {
		add("\n## Conditional edges\n\n%d edge(s) depend on request-time conditions that cannot be resolved offline; included in path-finding only with --include-conditional.\n", n)
	}
	return os.WriteFile(path, b, 0o644)
}

type kv struct {
	k string
	v int
}

func sortedCounts(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].v != out[j].v {
			return out[i].v > out[j].v
		}
		return out[i].k < out[j].k
	})
	return out
}
