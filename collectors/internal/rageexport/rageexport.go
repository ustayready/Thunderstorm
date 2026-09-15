// Package rageexport converts a Thunderstorm engagement into the RAGE single-file
// format: one NDJSON stream, line 1 a manifest, every other line a `kind`-tagged
// record. See the RAGE spec (github.com/trustedsec/rage, spec/format.md).
//
// RunWorkdir(wd) reads a scan workdir — bundle/full/{facts,ledger,exposure} + graph/
// — and emits FULL RAGE: real `evidence` records from the collection ledger (the API
// operations), `fact` records from the normalized observations, and edges linked to
// the facts that justify them.
//
// Output: if outPath ends in ".zip", writes a zip containing graph.rage.ndjson (for
// upload size); otherwise a raw .rage.ndjson.
package rageexport

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	assets "thunderstorm/collector"
)

// Stats reports what the conversion emitted.
type Stats struct {
	Nodes, Edges, Facts, Evidence, Findings, Surfaces, Paths int
	RealEvidence                                             bool // true when evidence came from the ledger/facts (workdir), not synthesized
}

// sources is the normalized input the emitter works from, populated from a zip or a workdir.
type sources struct {
	manifest                                           map[string]any
	nodes, edges, paths, hits, surfaces, facts, ledger []map[string]any
	full                                               bool // came from a workdir (has facts/ledger)
}

// RunWorkdir converts a scan workdir (bundle/full + graph) into FULL RAGE with real evidence.
func RunWorkdir(wd, outPath string) (Stats, error) {
	g := filepath.Join(wd, "graph")
	if _, err := os.Stat(filepath.Join(g, "nodes.ndjson")); err != nil {
		return Stats{}, fmt.Errorf("%s is not a scan workdir (missing graph/nodes.ndjson)", wd)
	}
	bf := filepath.Join(wd, "bundle", "full")
	// The engine's graph manifest lacks caller_arn; the collector's bundle manifest
	// carries it. Merge it in so the RAGE manifest can set scope.foothold.
	gman := loadObject(filepath.Join(g, "manifest.json"))
	if gman == nil {
		gman = map[string]any{}
	}
	if str(gman["caller_arn"]) == "" {
		if bman := loadObject(filepath.Join(bf, "manifest.json")); bman != nil {
			gman["caller_arn"] = bman["caller_arn"]
		}
	}
	src := sources{
		full:     true,
		manifest: gman,
		nodes:    loadNDJSON(filepath.Join(g, "nodes.ndjson")),
		edges:    loadNDJSON(filepath.Join(g, "edges.ndjson")),
		paths:    loadNDJSON(filepath.Join(g, "paths.ndjson")),
		hits:     loadNDJSON(filepath.Join(bf, "exposure", "hits.ndjson")),
		surfaces: loadNDJSON(filepath.Join(bf, "exposure", "surfaces.ndjson")),
		facts:    loadGlob(filepath.Join(bf, "facts")),
		ledger:   loadGlob(filepath.Join(bf, "ledger")),
	}
	return emit(src, outPath)
}

// emit is the shared writer: manifest, nodes, evidence, facts, edges, findings, surfaces, paths.
func emit(src sources, outPath string) (Stats, error) {
	var st Stats
	st.RealEvidence = src.full
	var lines [][]byte
	add := func(rec map[string]any) error {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		lines = append(lines, b)
		return nil
	}

	idx := buildNodeIndex(src.nodes)

	// The collecting identity (caller_arn) is the default foothold. Per the RAGE
	// spec scope.foothold is a node_id, so resolve the caller's ARN to its node.
	foothold := ""
	if c := str(src.manifest["caller_arn"]); c != "" {
		foothold = resolveRef(c, idx)
	}

	// line 1: manifest.
	if err := add(buildManifest(src.manifest, foothold, len(src.nodes), len(src.edges),
		len(src.facts), len(src.hits), len(src.surfaces), len(src.paths))); err != nil {
		return st, err
	}

	// nodes.
	for _, n := range src.nodes {
		n["kind"] = "node"
		if nt := str(n["node_type"]); nt != "" {
			n["node_type"] = mapNodeType(nt)
		}
		if err := add(n); err != nil {
			return st, err
		}
		st.Nodes++
	}

	// evidence from the ledger (real API-operation receipts). Index by resource_type so facts
	// can link back to the operation that collected them.
	evSeen := map[string]bool{}
	var evRecs []map[string]any
	evByNorm := map[string][]string{} // normalized resource-type -> evidence ids
	for _, op := range src.ledger {
		id, rec := ledgerEvidence(op)
		if id == "" {
			continue
		}
		if !evSeen[id] {
			evSeen[id] = true
			evRecs = append(evRecs, rec)
		}
		if rt := str(op["resource_type"]); rt != "" {
			evByNorm[normType(rt)] = appendUniq(evByNorm[normType(rt)], id)
		}
	}

	// facts (real observations). Assign fact_id + content_hash, link to evidence, index by
	// (source,target) so derived edges can point at the facts that justify them.
	factsBySrcTgt := map[string][]string{}
	factEvidence := map[string][]string{}
	for _, f := range src.facts {
		fid := factID(f) // natural key — identical to engine model.FactID, so edge.facts align
		orig, _ := json.Marshal(f)
		if ft, ok := f["kind"].(string); ok && ft != "" {
			f["fact_type"] = ft // preserve original fact type before overwriting kind
		}
		f["kind"] = "fact"
		f["fact_id"] = fid
		f["content_hash"] = "sha256:" + hashHex(orig)
		// facts reference resources by native id — resolve to node_ids so they join the graph
		// and so edges (which use node_ids) can point at the facts that justify them.
		rs := resolveRef(str(f["source"]), idx)
		rt := resolveRef(str(f["target"]), idx)
		f["source"], f["target"] = rs, rt
		// fact -> evidence: the collection op whose resource_type matches this fact's type.
		if ev := matchNorm(normType(str(f["fact_type"])), evByNorm); len(ev) > 0 {
			f["evidence"] = ev
			factEvidence[fid] = ev
		}
		factsBySrcTgt[rs+"\x00"+rt] = append(factsBySrcTgt[rs+"\x00"+rt], fid)
	}

	// edges: map nature, link to supporting facts, attach evidence (real from facts, else
	// synthesized so the derived⇒evidence rule always holds).
	// index edges so a derived edge can resolve its facts transitively through derived_from
	// (derived → parent edges → their engine-stamped facts). This closes the derived-edge gap.
	edgeByID := map[string]map[string]any{}
	for _, e := range src.edges {
		edgeByID[str(e["edge_id"])] = e
	}
	var resolveFacts func(id string, seen map[string]bool) []string
	resolveFacts = func(id string, seen map[string]bool) []string {
		e := edgeByID[id]
		if e == nil || seen[id] {
			return nil
		}
		seen[id] = true
		if ex := strSlice(e["facts"]); len(ex) > 0 {
			return ex // explicit, engine-stamped
		}
		var out []string
		for _, pid := range strSlice(e["derived_from"]) {
			for _, fid := range resolveFacts(pid, seen) {
				out = appendUniq(out, fid)
			}
		}
		return out
	}

	for _, e := range src.edges {
		inlineEv, _ := e["evidence"].(map[string]any)
		delete(e, "evidence")
		e["kind"] = "edge"
		e["nature"] = mapNature(str(e["nature"]))
		// provenance: explicit engine facts → transitive via derived_from → src/tgt heuristic
		facts := strSlice(e["facts"])
		if len(facts) == 0 {
			facts = resolveFacts(str(e["edge_id"]), map[string]bool{})
		}
		if len(facts) == 0 {
			facts = factsBySrcTgt[str(e["source"])+"\x00"+str(e["target"])]
		}
		if len(facts) > 0 {
			e["facts"] = facts
			var evids []string
			for _, fid := range facts {
				for _, ev := range factEvidence[fid] {
					evids = appendUniq(evids, ev)
				}
			}
			if len(evids) > 0 {
				e["evidence"] = evids
			}
		}
		if e["evidence"] == nil && (e["nature"] == "derived" || inlineEv != nil) {
			id, rec := synthEvidence(inlineEv, e)
			e["evidence"] = id
			if !evSeen[id] {
				evSeen[id] = true
				evRecs = append(evRecs, rec)
			}
		}
	}

	// write evidence + facts (after edges so synthesized fallbacks are included).
	for _, ev := range evRecs {
		if err := add(ev); err != nil {
			return st, err
		}
		st.Evidence++
	}
	for _, f := range src.facts {
		if err := add(f); err != nil {
			return st, err
		}
		st.Facts++
	}
	// Dedupe edges by edge_id: RAGE's edge_id is deterministic on (type|source|target|scope), so two
	// records that share it are the same relationship observed via different permissions — merge them
	// (union permissions/conditions/facts) rather than emit a colliding, non-conformant duplicate.
	byEID := map[string]map[string]any{}
	var order []map[string]any
	for _, e := range src.edges {
		id := str(e["edge_id"])
		if prev, ok := byEID[id]; ok && id != "" {
			for _, f := range []string{"permissions", "conditions", "facts"} {
				if u := unionSlices(prev[f], e[f]); len(u) > 0 {
					prev[f] = u
				}
			}
			continue
		}
		byEID[id] = e
		order = append(order, e)
	}
	for _, e := range order {
		if err := add(e); err != nil {
			return st, err
		}
		st.Edges++
	}
	for _, h := range src.hits {
		h["kind"] = "finding"
		if rid := str(h["resource_id"]); rid != "" {
			h["resource_id"] = resolveRef(rid, idx)
		}
		if err := add(h); err != nil {
			return st, err
		}
		st.Findings++
	}
	for _, s := range src.surfaces {
		s["kind"] = "surface"
		if rid := str(s["resource_id"]); rid != "" {
			s["resource_id"] = resolveRef(rid, idx)
		}
		if err := add(s); err != nil {
			return st, err
		}
		st.Surfaces++
	}
	for _, p := range src.paths {
		p["kind"] = "path"
		if err := add(p); err != nil {
			return st, err
		}
		st.Paths++
	}

	return st, writeOut(outPath, lines)
}

func buildManifest(m map[string]any, foothold string, nNodes, nEdges, nFacts, nHits, nSurf, nPaths int) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	scope := map[string]any{}
	if p := str(m["provider"]); p != "" {
		scope["providers"] = []any{p}
	}
	if foothold != "" {
		scope["foothold"] = foothold // node_id of the collecting identity
	}
	producer := map[string]any{}
	for src, dst := range map[string]string{"collector_version": "collector", "engine_version": "engine", "catalog_contract_version": "catalog"} {
		if v := str(m[src]); v != "" {
			producer[dst] = v
		}
	}
	return map[string]any{
		"kind": "manifest", "spec_version": assets.RageVersion(),
		"created_at": str(m["created_at"]),
		"scope":      scope, "producer": producer,
		"counts": map[string]any{"nodes": nNodes, "edges": nEdges, "facts": nFacts,
			"findings": nHits, "surfaces": nSurf, "paths": nPaths},
	}
}

// ledgerEvidence turns a collection-ledger operation into a real RAGE evidence receipt.
func ledgerEvidence(op map[string]any) (string, map[string]any) {
	task := str(op["task_id"])
	if task == "" {
		task = hashOfMap(op)[:12]
	}
	id := "ev:op-" + task
	rec := map[string]any{"kind": "evidence", "evidence_id": id,
		"content_hash": "sha256:" + hashOfMap(op),
		"source":       str(op["operation"]), "status": str(op["status"]),
		"captured_at": str(op["ended_at"]), "scope": op["scope"]}
	return id, rec
}

// synthEvidence builds a content-addressed evidence record from an edge's inline evidence
// (or its rule/derivation identity) — the fallback when no ledger/fact evidence links up.
func synthEvidence(inline map[string]any, e map[string]any) (string, map[string]any) {
	detail := inline
	if detail == nil {
		detail = map[string]any{"rule_id": e["rule_id"], "type": e["type"],
			"source": e["source"], "target": e["target"], "derived_from": e["derived_from"]}
	}
	h := hashOfMap(detail)
	id := "ev:sha256-" + h[:16]
	rec := map[string]any{"kind": "evidence", "evidence_id": id,
		"content_hash": "sha256:" + h, "detail": detail}
	if rid := str(e["rule_id"]); rid != "" {
		rec["source"] = rid
	}
	return id, rec
}

func mapNature(n string) string {
	if n == "derived" {
		return "derived"
	}
	return "explicit" // RAGE instance nature is explicit|derived (vocab/edge-types.json)
}

// mapNodeType maps engine-internal node types to their canonical RAGE type.
func mapNodeType(t string) string {
	if t == "Everyone" {
		return "AnonymousIdentity" // RAGE's canonical public/anonymous principal
	}
	return t
}

// normType normalizes a type string for fuzzy matching: last ':'-segment, lowercased,
// alphanumerics only, trailing plural 's' dropped. So "azure:authorization:role-assignments"
// and a fact type "role_assignment" both normalize toward "roleassignment".
func normType(s string) string {
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	out := b.String()
	return strings.TrimSuffix(out, "s")
}

// matchNorm returns evidence ids whose normalized resource-type relates to nf (either is a
// substring of the other) — the fact-of-type-X ← op-collecting-resource-X link.
func matchNorm(nf string, evByNorm map[string][]string) []string {
	if nf == "" {
		return nil
	}
	var out []string
	for k, ids := range evByNorm {
		if k != "" && (strings.Contains(k, nf) || strings.Contains(nf, k)) {
			for _, id := range ids {
				out = appendUniq(out, id)
			}
		}
	}
	return out
}

// ---- node reference resolution (findings/surfaces reference native paths) ----

func buildNodeIndex(nodes []map[string]any) map[string]string {
	idx := map[string]string{}
	for _, n := range nodes {
		id := str(n["node_id"])
		if id == "" {
			continue
		}
		idx[id] = id
		if arn := str(n["arn"]); arn != "" {
			idx[arn] = id
		}
		if i := strings.LastIndexByte(id, '|'); i >= 0 {
			idx[id[i+1:]] = id
		}
	}
	return idx
}

func resolveRef(ref string, idx map[string]string) string {
	if id, ok := idx[ref]; ok {
		return id
	}
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		if id, ok := idx[ref[i+1:]]; ok {
			return id
		}
	}
	return ref
}

// ---- io helpers ----

func writeOut(outPath string, lines [][]byte) error {
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if strings.HasSuffix(outPath, ".zip") {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		zw := zip.NewWriter(f)
		w, err := zw.Create("graph.rage.ndjson")
		if err != nil {
			return err
		}
		if _, err := w.Write(buf.Bytes()); err != nil {
			return err
		}
		return zw.Close()
	}
	return os.WriteFile(outPath, buf.Bytes(), 0o644)
}

func loadNDJSON(path string) []map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseNDJSON(b)
}

func loadObject(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseObject(b)
}

func loadGlob(dir string) []map[string]any {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.ndjson"))
	var out []map[string]any
	for _, m := range matches {
		out = append(out, loadNDJSON(m)...)
	}
	return out
}

func parseNDJSON(b []byte) []map[string]any {
	var out []map[string]any
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if m := parseObject(line); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func parseObject(b []byte) map[string]any {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hashOfMap(m map[string]any) string {
	b, _ := json.Marshal(m)
	return hashHex(b)
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// unionSlices merges two string-ish fields into a deduped slice (nil if empty).
func unionSlices(a, b any) []string {
	var out []string
	for _, v := range strSlice(a) {
		out = appendUniq(out, v)
	}
	for _, v := range strSlice(b) {
		out = appendUniq(out, v)
	}
	return out
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// factID computes a fact's id from a natural key — identical to engine model.FactID
// (provider|kind|source|target|edge_hint|scope.account) — so engine-stamped edge.facts
// resolve to the fact records emitted here. Uses the RAW source/target (native refs), which
// is what the engine hashed. Keep in lockstep with model.FactID.
func factID(f map[string]any) string {
	account := ""
	if sc, ok := f["scope"].(map[string]any); ok {
		account = str(sc["account"])
	}
	key := str(f["provider"]) + "|" + str(f["kind"]) + "|" + str(f["source"]) + "|" +
		str(f["target"]) + "|" + str(f["edge_hint"]) + "|" + account
	return "fact-" + hashHex([]byte(key))[:12]
}
