// Multi-scope collection: run the per-scope collector over a LIST of scopes
// (AWS profiles / GCP projects / Azure subscriptions), then merge every scope's
// Evidence Bundle into ONE `full/` tree so the engine builds a single unified
// graph spanning all of them. Node ids already embed the scope
// (<provider>|<account>|<kind>|<native-id>), so the merge is collision-free and
// cross-scope edges connect naturally. See docs/multi-cloud/.
package run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	azureprov "thunderstorm/collector/internal/providers/azure"
	gcpprov "thunderstorm/collector/internal/providers/gcp"
)

// Scope is one collection target within a multi-scope run.
type Scope struct {
	Provider      string // aws | gcp | azure
	Ident         string // AWS profile | GCP project | Azure subscription id
	ImpersonateSA string // GCP only, optional
}

// options derives per-scope collector Options from a shared base.
func (s Scope) options(base Options) Options {
	o := base
	o.Provider = s.Provider
	o.Profile, o.Project, o.Subscription = "", "", ""
	switch s.Provider {
	case "aws":
		o.Profile = s.Ident
	case "gcp":
		o.Project = s.Ident
		if s.ImpersonateSA != "" {
			o.ImpersonateSA = s.ImpersonateSA
		}
	case "azure":
		o.Subscription = s.Ident
	}
	return o
}

// ScopeResult is the per-scope outcome recorded in the engagement manifest.
type ScopeResult struct {
	Provider  string `json:"provider"`
	Ident     string `json:"ident"`
	Account   string `json:"account,omitempty"`
	Caller    string `json:"caller_arn,omitempty"`
	Status    string `json:"status"` // ok | error
	Error     string `json:"error,omitempty"`
	Catalog   string `json:"-"` // catalog contract version (internal, for the engagement manifest)
	bundleDir string // per-scope full/ dir (internal)
}

// Selector describes how scopes were requested on the CLI.
type Selector struct {
	ScopesFile  string // --scopes  (unified provider:scope file)
	AWSProfiles string // --aws-profiles  (file path or csv)
	GCPProjects string // --gcp-projects  (file path or csv)
	AzureSubs   string // --azure-subscriptions (file path or csv)
	MaxScopes   int    // --max-scopes  (0 = unlimited)
}

// Explicit reports whether any multi-scope selector flag was supplied.
func (s Selector) Explicit() bool {
	return s.ScopesFile != "" || s.AWSProfiles != "" || s.GCPProjects != "" || s.AzureSubs != ""
}

// ResolveScopes turns CLI flags into a concrete scope list. Precedence:
//  1. explicit --scopes / per-provider flags (files or csv);
//  2. otherwise DISCOVERY for base.Provider (the zero-config default).
//
// Discovery only ever surfaces scopes the caller is already authorized to see.
func ResolveScopes(ctx context.Context, base Options, sel Selector) ([]Scope, string, error) {
	if sel.ScopesFile != "" {
		sc, err := parseScopesFile(sel.ScopesFile)
		return sc, "explicit", err
	}
	if sel.Explicit() {
		var sc []Scope
		for _, id := range readList(sel.AWSProfiles) {
			sc = append(sc, Scope{Provider: "aws", Ident: id})
		}
		for _, id := range readList(sel.GCPProjects) {
			sc = append(sc, Scope{Provider: "gcp", Ident: id})
		}
		for _, id := range readList(sel.AzureSubs) {
			sc = append(sc, Scope{Provider: "azure", Ident: id})
		}
		return sc, "explicit", nil
	}
	// discovery default
	sc, err := discoverScopes(ctx, base)
	return sc, "discovery", err
}

// discoverScopes enumerates every scope base.Provider's credentials can reach.
func discoverScopes(ctx context.Context, base Options) ([]Scope, error) {
	switch base.Provider {
	case "gcp":
		projs, err := gcpprov.DiscoverProjects(ctx)
		if err != nil {
			return nil, fmt.Errorf("gcp project discovery failed (is ADC valid, and does the caller have resourcemanager.projects.list?): %w", err)
		}
		var sc []Scope
		for _, p := range projs {
			sc = append(sc, Scope{Provider: "gcp", Ident: p, ImpersonateSA: base.ImpersonateSA})
		}
		return sc, nil
	case "azure":
		cli, err := azureprov.Load(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("azure subscription discovery failed (is `az login` valid?): %w", err)
		}
		var sc []Scope
		for _, sub := range cli.Subscriptions() {
			sc = append(sc, Scope{Provider: "azure", Ident: sub})
		}
		return sc, nil
	case "aws":
		// AWS org-wide discovery needs assume-role wiring per account; for now a
		// bare run collects the single account of the active credentials. Use
		// --aws-profiles to collect multiple accounts.
		return []Scope{{Provider: "aws", Ident: base.Profile}}, nil
	}
	return nil, fmt.Errorf("discovery unsupported for provider %q", base.Provider)
}

// CollectScopes runs the collector once per scope into workDir/scope-NNN, isolating
// failures (a denied scope is recorded, not fatal). With base.ScopeConcurrency > 1 the
// scopes run in a bounded worker pool (essential at hundreds of projects) with quiet
// per-scope output and a live progress line; otherwise sequential with full output.
// Results are returned in scope order regardless of completion order.
func CollectScopes(ctx context.Context, base Options, scopes []Scope, workDir string) []ScopeResult {
	conc := base.ScopeConcurrency
	if conc < 1 {
		conc = 1
	}
	results := make([]ScopeResult, len(scopes))
	if conc == 1 {
		for i, s := range scopes {
			fmt.Printf("\n── scope %d/%d · %s:%s ──\n", i+1, len(scopes), s.Provider, s.Ident)
			results[i] = collectOne(ctx, base, s, i, workDir, false)
		}
		return results
	}
	fmt.Printf("collecting %d scopes · %d in parallel\n", len(scopes), conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	done := 0
	for i, s := range scopes {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s Scope) {
			defer wg.Done()
			defer func() { <-sem }()
			r := collectOne(ctx, base, s, i, workDir, true)
			mu.Lock()
			results[i] = r
			done++
			n := done
			mu.Unlock()
			status := r.Account
			if r.Status != "ok" {
				status = "FAILED: " + firstLine(r.Error)
			}
			fmt.Printf("  [%d/%d] %s:%s — %s\n", n, len(scopes), r.Provider, r.Ident, status)
		}(i, s)
	}
	wg.Wait()
	return results
}

// collectOne runs the collector for a single scope into workDir/scope-NNN.
func collectOne(ctx context.Context, base Options, s Scope, i int, workDir string, quiet bool) ScopeResult {
	o := s.options(base)
	o.Out = filepath.Join(workDir, fmt.Sprintf("scope-%03d", i))
	o.Quiet = quiet
	r := ScopeResult{Provider: s.Provider, Ident: s.Ident}
	res, err := Collect(ctx, o)
	if err != nil {
		r.Status, r.Error = "error", err.Error()
		if !quiet {
			fmt.Printf("  scope failed: %v\n  (continuing — recorded in the engagement manifest)\n", err)
		}
		return r
	}
	r.Status, r.Account, r.Caller, r.bundleDir = "ok", res.Account, res.Manifest.CallerARN, res.BundleDir
	r.Catalog = res.Manifest.Version.CatalogContractVersion
	return r
}

// firstLine returns the first line of s, truncated, for a one-line progress status.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

// MergeBundles unions every successful scope's full/ tree into mergedFull. Inventory
// records are de-duplicated by node_id (so e.g. a shared Entra tenant collected under
// several Azure subscriptions appears once); facts/exposure lines are de-duplicated
// verbatim; the coverage ledger is concatenated; blobs are unioned by content hash.
func MergeBundles(results []ScopeResult, mergedFull string) error {
	for _, sub := range []string{"inventory", "facts", "exposure", "ledger", "blobs"} {
		if err := os.MkdirAll(filepath.Join(mergedFull, sub), 0o755); err != nil {
			return err
		}
	}
	seenNode := map[string]bool{} // dedup inventory across all scopes by node_id
	seenLine := map[string]bool{} // dedup facts/exposure verbatim
	invOut := map[string]*os.File{}
	defer func() {
		for _, f := range invOut {
			f.Close()
		}
	}()

	for _, r := range results {
		if r.Status != "ok" || r.bundleDir == "" {
			continue
		}
		// inventory: one merged shard per resource-type filename, deduped by node_id
		invDir := filepath.Join(r.bundleDir, "inventory")
		if ents, err := os.ReadDir(invDir); err == nil {
			for _, e := range ents {
				if e.IsDir() {
					continue
				}
				out := invOut[e.Name()]
				if out == nil {
					f, err := os.Create(filepath.Join(mergedFull, "inventory", e.Name()))
					if err != nil {
						return err
					}
					invOut[e.Name()], out = f, f
				}
				if err := eachLine(filepath.Join(invDir, e.Name()), func(line []byte) error {
					var rec struct {
						NodeID string `json:"node_id"`
					}
					_ = json.Unmarshal(line, &rec)
					if rec.NodeID != "" {
						if seenNode[rec.NodeID] {
							return nil
						}
						seenNode[rec.NodeID] = true
					}
					_, err := out.Write(append(line, '\n'))
					return err
				}); err != nil {
					return err
				}
			}
		}
		// facts: merged per-kind shard, deduped verbatim
		if err := mergeDir(filepath.Join(r.bundleDir, "facts"), filepath.Join(mergedFull, "facts"), seenLine); err != nil {
			return err
		}
		// exposure: hits/surfaces are single files, deduped verbatim
		for _, name := range []string{"hits.ndjson", "surfaces.ndjson"} {
			if err := appendDedup(filepath.Join(r.bundleDir, "exposure", name), filepath.Join(mergedFull, "exposure", name), seenLine); err != nil {
				return err
			}
		}
		// ledger coverage: concatenated (per-scope coverage, no dedup)
		if err := appendDedup(filepath.Join(r.bundleDir, "ledger", "coverage.ndjson"), filepath.Join(mergedFull, "ledger", "coverage.ndjson"), nil); err != nil {
			return err
		}
		// blobs: union by filename (content hash)
		blobDir := filepath.Join(r.bundleDir, "blobs")
		if ents, err := os.ReadDir(blobDir); err == nil {
			for _, e := range ents {
				if e.IsDir() {
					continue
				}
				dst := filepath.Join(mergedFull, "blobs", e.Name())
				if _, err := os.Stat(dst); err == nil {
					continue
				}
				copyFile(filepath.Join(blobDir, e.Name()), dst)
			}
		}
	}
	// Write the merged manifest so the engine routes effective-permission evaluation.
	// provider = the single provider when homogeneous, else "multi" (the engine then runs
	// every provider present in the facts). WITHOUT this the engine sees no provider and
	// derives ZERO permission edges from the merged facts.
	provSet := map[string]bool{}
	for _, r := range results {
		if r.Status == "ok" {
			provSet[r.Provider] = true
		}
	}
	prov := "multi"
	if len(provSet) == 1 {
		for p := range provSet {
			prov = p
		}
	}
	// Carry each scope's caller identity so the engine can seed a "you are here" foothold
	// node per scope (a human ADC identity often holds no project-scoped binding and would
	// otherwise be absent from the graph).
	scopes := make([]map[string]any, 0, len(results))
	for _, r := range results {
		if r.Status == "ok" {
			scopes = append(scopes, map[string]any{
				"provider": r.Provider, "account": r.Account, "caller_arn": r.Caller})
		}
	}
	man, _ := json.MarshalIndent(map[string]any{
		"provider": prov, "account": "multi", "scopes": scopes}, "", "  ")
	if err := os.WriteFile(filepath.Join(mergedFull, "manifest.json"), man, 0o644); err != nil {
		return err
	}
	return nil
}

// mergeDir concatenates every ndjson shard under src into the same-named shard under
// dst, de-duplicating lines verbatim via seen.
func mergeDir(src, dst string, seen map[string]bool) error {
	ents, err := os.ReadDir(src)
	if err != nil {
		return nil // absent tier — fine
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if err := appendDedup(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), seen); err != nil {
			return err
		}
	}
	return nil
}

// appendDedup appends src's lines onto dst (created/append), skipping verbatim
// duplicates when seen != nil.
func appendDedup(src, dst string, seen map[string]bool) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return eachLine(src, func(line []byte) error {
		if seen != nil {
			k := string(line)
			if seen[k] {
				return nil
			}
			seen[k] = true
		}
		_, err := f.Write(append(line, '\n'))
		return err
	})
}

// eachLine invokes fn for every non-empty line of an ndjson file (absent = no-op).
func eachLine(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		if err := fn(cp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func copyFile(src, dst string) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer out.Close()
	_, _ = io.Copy(out, in)
}

// readList reads a scope list that is EITHER a file path (one entry per line, '#'
// comments) OR a comma-separated inline list. Empty in -> nil.
func readList(in string) []string {
	in = strings.TrimSpace(in)
	if in == "" {
		return nil
	}
	if data, err := os.ReadFile(in); err == nil {
		return parseLines(string(data))
	}
	var out []string
	for _, p := range strings.Split(in, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseScopesFile reads the unified `provider:scope` scope file.
func parseScopesFile(path string) ([]Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading scopes file: %w", err)
	}
	var sc []Scope
	for _, ln := range parseLines(string(data)) {
		prov, ident, ok := strings.Cut(ln, ":")
		prov = strings.TrimSpace(strings.ToLower(prov))
		ident = strings.TrimSpace(ident)
		if !ok || ident == "" || (prov != "aws" && prov != "gcp" && prov != "azure") {
			return nil, fmt.Errorf("bad scope line %q (expected provider:scope, provider in aws|gcp|azure)", ln)
		}
		sc = append(sc, Scope{Provider: prov, Ident: ident})
	}
	return sc, nil
}

// parseLines returns non-empty, non-comment trimmed lines.
func parseLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}
