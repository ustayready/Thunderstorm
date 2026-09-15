# Thunderstorm Collector

The gather-and-generate layer behind `thunderstorm scan`. Authenticates to a cloud
account (read-only), collects an **Evidence Bundle** (internal NDJSON), builds the
attack-path graph, and emits it as a **RAGE `engagement.zip`**. The bundle/graph
live in a scratch workdir that's removed after the run — the only artifact you keep
is the RAGE zip.

**Providers:** AWS, GCP, Azure. **Catalog contract:** consumes RAGE
`catalog_contract_version` 1.x (see `COMPATIBILITY.yaml`); the vendored RAGE
snapshot lives in `rage/` and is embedded into the binary.

## Build

From the repo root (produces `./bin/thunderstorm`):

```bash
make
```

## Run (read-only)

```bash
# whole account, all collectable regions → ./output/thunderstorm-<provider>-<account>-<ts>.zip
./bin/thunderstorm scan --profile thunderstorm

# scope to specific regions; write to a chosen path
./bin/thunderstorm scan --profile thunderstorm --only-regions us-east-1,us-west-2
./bin/thunderstorm scan --profile thunderstorm --out engagement.zip

./bin/thunderstorm version
```

Flags: `--profile` (AWS shared-config profile), `--out` (`.zip` path or directory;
default `./output/`), `--region` (bootstrap region for global calls),
`--only-regions`, `--concurrency`, multi-scope flags (`--scopes`, `--aws-profiles`,
`--gcp-projects`, `--azure-subscriptions`, `--scope-concurrency`), `--keep-workdir`.

## What it does

- **Auth + scope discovery** — verifies the caller, discovers collectable
  regions/projects/subscriptions, and records a coverage ledger so gaps are visible.
- **Registry-driven collection** — a DAG of `enumerate → bound detail` calls whose
  recipes come entirely from RAGE `providers/<provider>.json` (never a local schema).
- **Exposure probing** — read-only probes of the RAGE `exposure-db` catalog for
  real credential exposure; non-read sites are recorded as surfaces, never invoked.
- **Facts tier** — policy/trust/network facts emitted as edge hints for the engine.
- **Generate RAGE** — builds the graph and serializes everything (nodes, edges,
  paths, findings, surfaces, facts, evidence) into one `graph.rage.ndjson`.

## Output

`scan` writes a single RAGE engagement.zip (default under `./output/`, git-ignored
at any depth so engagement data never lands in the repo):

```
engagement.zip
└── graph.rage.ndjson   # RAGE single-file format: manifest + node/edge/path/finding/surface/fact/evidence
```

Blaze ingests this directly and derives its view from the RAGE manifest + records.

## Tests

```bash
go test ./...   # binding resolution, unresolved-binding safety, bulkhead isolation
```
