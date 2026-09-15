// Package graph loads a built node/edge set into an in-memory directed graph and
// answers path queries (shortest path by edge weight, reachability).
package graph

import (
	"container/heap"
	"sort"

	"thunderstorm/engine/internal/model"
)

// Graph is an indexed, queryable view of nodes + edges.
type Graph struct {
	nodes map[string]model.Node
	edges map[string]model.Edge
	out   map[string][]string // node_id -> outgoing edge_ids
	in    map[string][]string // node_id -> incoming edge_ids
}

// New indexes nodes and edges for querying. If includeConditional is false,
// edges whose state is not ACTIVE are excluded from traversal (but still stored).
func New(nodes []model.Node, edges []model.Edge, includeConditional bool) *Graph {
	g := &Graph{
		nodes: make(map[string]model.Node, len(nodes)),
		edges: make(map[string]model.Edge, len(edges)),
		out:   map[string][]string{},
		in:    map[string][]string{},
	}
	for _, n := range nodes {
		g.nodes[n.NodeID] = n
	}
	for _, e := range edges {
		if e.EdgeID == "" {
			// defensive: never let an unkeyed edge collide on "" and corrupt the index.
			e.EdgeID = model.EdgeID(e.Type, e.Source, e.Target, e.Scope)
		}
		g.edges[e.EdgeID] = e
		if !includeConditional && e.State != model.StateActive {
			continue
		}
		g.out[e.Source] = append(g.out[e.Source], e.EdgeID)
		g.in[e.Target] = append(g.in[e.Target], e.EdgeID)
	}
	return g
}

// Node returns a node by id.
func (g *Graph) Node(id string) (model.Node, bool) { n, ok := g.nodes[id]; return n, ok }

// Edge returns an edge by id.
func (g *Graph) Edge(id string) (model.Edge, bool) { e, ok := g.edges[id]; return e, ok }

// ShortestPath returns the least-weight directed path from -> to, as an ordered
// edge-id list, or nil if unreachable. Dijkstra over edge Weight.
func (g *Graph) ShortestPath(from, to string) ([]string, float64) {
	const inf = 1e18
	dist := map[string]float64{from: 0}
	prevEdge := map[string]string{}
	visited := map[string]bool{}

	pq := &pqueue{}
	heap.Init(pq)
	heap.Push(pq, item{node: from, cost: 0})

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(item)
		if visited[cur.node] {
			continue
		}
		visited[cur.node] = true
		if cur.node == to {
			break
		}
		for _, eid := range g.out[cur.node] {
			e := g.edges[eid]
			nd := cur.cost + edgeWeight(e)
			if d, ok := dist[e.Target]; !ok || nd < d {
				dist[e.Target] = nd
				prevEdge[e.Target] = eid
				heap.Push(pq, item{node: e.Target, cost: nd})
			}
		}
	}

	if _, ok := dist[to]; !ok || to == from {
		if to == from {
			return []string{}, 0
		}
		return nil, inf
	}
	// reconstruct
	var rev []string
	for at := to; at != from; {
		eid := prevEdge[at]
		if eid == "" {
			return nil, inf
		}
		rev = append(rev, eid)
		at = g.edges[eid].Source
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, dist[to]
}

// Reaches returns all node ids reachable from `from` (forward BFS).
func (g *Graph) Reaches(from string) []string {
	seen := map[string]bool{from: true}
	queue := []string{from}
	var out []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, eid := range g.out[cur] {
			t := g.edges[eid].Target
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
				queue = append(queue, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ReachedBy returns all node ids that can reach `to` (backward BFS) — "who can
// reach X".
func (g *Graph) ReachedBy(to string) []string {
	seen := map[string]bool{to: true}
	queue := []string{to}
	var out []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, eid := range g.in[cur] {
			s := g.edges[eid].Source
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
				queue = append(queue, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

func edgeWeight(e model.Edge) float64 {
	if e.Weight <= 0 {
		return 1.0
	}
	return e.Weight
}

// --- priority queue ---

type item struct {
	node string
	cost float64
}
type pqueue []item

func (p pqueue) Len() int           { return len(p) }
func (p pqueue) Less(i, j int) bool { return p[i].cost < p[j].cost }
func (p pqueue) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *pqueue) Push(x any)        { *p = append(*p, x.(item)) }
func (p *pqueue) Pop() any {
	old := *p
	n := len(old)
	it := old[n-1]
	*p = old[:n-1]
	return it
}
