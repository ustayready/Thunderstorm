# Thunderstorm → RAGE export — Decisions (log)

`thunderstorm rage` converts an engagement into the Open Attack Graph format.

## Two sources
- `--in <engagement.zip>`: graph-only. The packaged zip discarded the Evidence Bundle, so evidence
  is **synthesized** (content-hash of the edge's inline evidence / rule) — honest but shallow.
- `--from <scan-workdir>` (a `--keep-workdir` run): reads `bundle/full/{facts,ledger,exposure}` +
  `graph/` and emits **FULL RAGE with real evidence**. This is the intended path.

## Mapping
- Add `kind` tags to all records. `nature`: Thunderstorm `explicit`→`observed`, `derived`→`derived`,
  `both`→`observed`.
- **`evidence` records = collection-ledger operations** (`bundle/full/ledger`): source=operation,
  status, captured_at=ended_at, content_hash=sha256(op). Real API receipts.
- **`fact` records = normalized facts** (`bundle/full/facts`): original fact `kind`→`fact_type`,
  fact_id=`fact-<sha12>`, content_hash. Fact `source/target` are native refs → **resolved to
  node_ids** (same resolver used for findings) so facts join the graph.
- **fact → evidence link**: fuzzy match `normType(fact_type)` against ledger `normType(resource_type)`
  (last `:`-segment, alnum, drop trailing plural). Rigorous-enough (a `role_assignment` fact ← the
  `…:role-assignments` collection op). Unmatched facts still stand as real observations.
- **edge → fact link**: an edge points at facts whose resolved `(source,target)` equal the edge's.
  Links *observed* edges well; *derived* edges usually don't match (see the gap).
- **derived⇒evidence**: guaranteed — if no fact-derived evidence links, synthesize a content-hashed
  evidence record from the rule/derivation so the RAGE rule always holds.
- **findings** = exposure hits; **surfaces**/**paths** kept as optional RAGE kinds → lossless.
- Output zipped when `--out` ends in `.zip` (`graph.rage.ndjson` inside) for upload size.

## Verified (counts only; no engagement values surfaced)
- Real Azure(`923908…`) + AWS(`do`) scan workdirs → valid RAGE; Azure 1030/1030 facts linked to
  evidence, AWS 71/99; observed edges link to facts; 0 dangling refs. ts-gcp.zip → valid graph-only.
- Round-trip into Blaze preserved everything (exposures, facts, evidence).

## Provenance — now rigorous (fixed)
- The engine stamps `Facts:[FactID]` on observed edges (build.directFact, evaluator_gcp grants,
  evaluator_azure RBAC + Entra). `model.FactID` and this package's `factID` compute the SAME natural
  key (`provider|kind|source|target|edge_hint|scope.account`), so edge.facts resolve to fact records.
- The exporter reads explicit `edge.facts`, else resolves **transitively via `derived_from`** (derived
  → parent edges → their facts), else falls back to the src/tgt heuristic. Verified: Azure 132/132
  derived edges now carry facts.
- **AWS policy edges now covered:** `Store.Evaluate` returns `Decision.Facts` (contributing policy
  docs); trust/resource-policy edges in build.go stamp facts too. Verified: AWS 91/91 edges carry
  facts (6/6 derived), Azure 150/150. Full provenance chain across all three providers.
