// Package run exposes the engine pipeline as a callable library so the
// `thunderstorm` binary can build a graph in-process (no subprocess).
package run

import (
	"fmt"
	"path/filepath"
	"time"

	"thunderstorm/engine/internal/bundle"
	"thunderstorm/engine/internal/output"
	"thunderstorm/engine/internal/pipeline"
)

const Version = "0.1.0"

// DefaultGraphOut is the per-engagement graph directory under ./output/ (in the
// current working directory) used when no --out is supplied — mirrors the
// collector's default so nothing is ever written into the source tree.
func DefaultGraphOut(provider, account string, at time.Time) string {
	return filepath.Join("output", fmt.Sprintf("thunderstorm-%s-%s-%s",
		provider, account, at.Format("20060102T150405Z")), "graph")
}

// BuildGraph reads an Evidence Bundle at bundleDir and writes the graph artifact
// (nodes/edges/paths.ndjson + manifest.json + report.md) to outDir. An empty
// outDir defaults to ./output/<engagement>/graph. at is the build timestamp
// (passed in so callers control determinism). Returns the resolved output dir.
func BuildGraph(bundleDir, outDir string, at time.Time) (output.Manifest, string, error) {
	b, err := bundle.Load(bundleDir)
	if err != nil {
		return output.Manifest{}, "", err
	}
	if outDir == "" {
		outDir = DefaultGraphOut(b.Manifest.Provider, b.Manifest.Account, at)
	}
	nodes, edges, _ := pipeline.Run(b, at)
	man := output.Manifest{
		EngineVersion:          Version,
		SourceBundle:           bundleDir,
		CatalogContractVersion: b.Manifest.Version.CatalogContractVersion,
		Provider:               b.Manifest.Provider,
		Account:                b.Manifest.Account,
		BuiltAt:                at,
		// Set counts here too: output.Write receives man by value and mutates its
		// own copy, so the caller's returned manifest needs them set explicitly.
		Counts: map[string]int{"nodes": len(nodes), "edges": len(edges), "paths": 0},
	}
	if err := output.Write(outDir, nodes, edges, nil, man); err != nil {
		return output.Manifest{}, "", err
	}
	return man, outDir, nil
}
