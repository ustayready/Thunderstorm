package graph

import (
	"testing"

	"thunderstorm/engine/internal/model"
)

func TestShortestPathDirectEdge(t *testing.T) {
	nodes := []model.Node{{NodeID: "A"}, {NodeID: "B"}}
	edges := []model.Edge{{EdgeID: "e1", Type: "CanReadData", Source: "A", Target: "B", State: model.StateActive, Weight: 2}}
	g := New(nodes, edges, false)

	path, cost := g.ShortestPath("A", "B")
	if path == nil {
		t.Fatalf("expected a path A->B, got nil")
	}
	if len(path) != 1 || path[0] != "e1" {
		t.Errorf("path = %v want [e1]", path)
	}
	if cost != 2 {
		t.Errorf("cost = %v want 2", cost)
	}
}

func TestShortestPathTwoHops(t *testing.T) {
	nodes := []model.Node{{NodeID: "A"}, {NodeID: "B"}, {NodeID: "C"}}
	edges := []model.Edge{
		{EdgeID: "e1", Source: "A", Target: "B", State: model.StateActive, Weight: 1},
		{EdgeID: "e2", Source: "B", Target: "C", State: model.StateActive, Weight: 1},
	}
	g := New(nodes, edges, false)
	path, cost := g.ShortestPath("A", "C")
	if len(path) != 2 || cost != 2 {
		t.Errorf("path=%v cost=%v want 2 hops cost 2", path, cost)
	}
}

func TestConditionalExcludedByDefault(t *testing.T) {
	nodes := []model.Node{{NodeID: "A"}, {NodeID: "B"}}
	edges := []model.Edge{{EdgeID: "e1", Source: "A", Target: "B", State: model.StateConditional, Weight: 1}}

	if path, _ := New(nodes, edges, false).ShortestPath("A", "B"); path != nil {
		t.Errorf("conditional edge should be excluded by default, got %v", path)
	}
	if path, _ := New(nodes, edges, true).ShortestPath("A", "B"); path == nil {
		t.Errorf("conditional edge should be included with includeConditional")
	}
}
