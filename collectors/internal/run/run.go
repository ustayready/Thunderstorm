// Package run is the collector flow as a callable library, so the `thunderstorm`
// binary can drive collection in-process. It returns errors instead of exiting.
package run

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"thunderstorm/collector/internal/exposure"
	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
	"thunderstorm/collector/internal/planner"
	"thunderstorm/collector/internal/progress"
	"thunderstorm/collector/internal/registry"
	"thunderstorm/collector/internal/scheduler"
	"thunderstorm/collector/internal/version"
)

// Options configures a collection run.
type Options struct {
	Profile          string
	Provider         string
	Out              string
	BootstrapRegion  string
	OnlyRegions      string
	RepoRoot         string
	Concurrency      int
	IncludeBlobs     bool
	Resume           bool
	Verbose          bool // print per-op detail; default is a concise summary
	Debug            bool // stream every op in/out/error to stderr (implies Verbose)
	Quiet            bool // suppress the per-scope console output (used in parallel multi-scope runs)
	ScopeConcurrency int  // multi-scope: how many scopes to collect in parallel (0/1 = sequential)

	// GCP
	Project       string // GCP project id (required for --provider gcp)
	ImpersonateSA string // optional service account to impersonate for the run

	// Azure
	Subscription string // optional single subscription id; empty = all accessible
}

// Stats is the machine-readable summary of a run — metadata + counts + timings.
// The CLI renders it; nothing here is verbose per-resource data.
type Stats struct {
	CallerARN string
	StartedAt time.Time

	RegionsDiscovered  int
	RegionsCollectable int
	RegionsNotOptedIn  int

	ResourceTypes int
	SkippedOps    int

	SeedTasks int
	Artifacts int

	ExposureTotal    int
	ExposureReadAPI  int
	ExposureSurfaces int
	ExposureProbed   int
	ExposureHits     int

	Facts int

	CollectDur  time.Duration
	ExposureDur time.Duration
	FactsDur    time.Duration
}

// Result reports what a collection produced.
type Result struct {
	BundleDir   string // <out>/full
	ExposureDir string // <out>/full/exposure
	Account     string
	Provider    string
	ZipPath     string
	Report      string
	IntegrityOK bool
	Manifest    model.Manifest
	Stats       Stats
}

// Collect runs the full collector flow and writes an Evidence Bundle + upload zip.
func Collect(ctx context.Context, opts Options) (*Result, error) {
	if opts.Provider == "" {
		opts.Provider = "aws"
	}
	if opts.Provider != "aws" && opts.Provider != "gcp" && opts.Provider != "azure" {
		return nil, fmt.Errorf("unsupported provider %q (aws|gcp|azure)", opts.Provider)
	}
	if opts.BootstrapRegion == "" {
		opts.BootstrapRegion = "us-east-1"
	}
	// opts.Out is resolved after provider setup (below): when the caller leaves it
	// empty we mint a per-engagement dir under ./output/ using the discovered
	// account + run timestamp, so concurrent/repeat runs never clobber each other.
	if opts.Concurrency <= 0 {
		opts.Concurrency = 12
	}
	// --debug turns on everything: per-op in/out/error to stderr AND the richer
	// verbose stdout breakdowns.
	if opts.Debug {
		opts.Verbose = true
	}
	pr := printer{quiet: opts.Quiet, verbose: opts.Verbose}
	// Locate the repo tree for live catalogs/manifests when running inside it.
	// Outside the repo (a shipped single binary), root stays "" and every loader
	// falls back to the assets embedded in the binary.
	root := opts.RepoRoot
	if root == "" {
		if r, err := FindRepoRoot(); err == nil {
			root = r
		}
	}

	// --- 1. Version reconciliation. ---
	contract, components, err := version.LoadContract(root)
	if err != nil {
		return nil, fmt.Errorf("loading catalog contract: %w", err)
	}
	if err := version.CheckCompatible(contract); err != nil {
		return nil, fmt.Errorf("catalog incompatible: %w", err)
	}
	pr.vprintf(opts.Verbose, "  %-*s %s\n", LabelWidth, "catalog",
		fmt.Sprintf("contract %s OK (collector %s supports %s)", contract, version.CollectorVersion, version.SupportedRange()))

	started := time.Now().UTC()
	stats := Stats{StartedAt: started}
	led := ledger.New()

	// --- 2. Provider setup: auth + scope discovery (records the ledger spine). ---
	onlyRegions := parseCSVSet(opts.OnlyRegions)
	bind, err := setupProvider(ctx, opts, led, onlyRegions)
	if err != nil {
		return nil, err
	}
	stats.CallerARN = bind.caller
	pr.kv("account", bind.account)
	pr.kv("caller", bind.caller)
	stats.RegionsDiscovered = bind.discovered
	stats.RegionsCollectable = len(bind.collectable)
	stats.RegionsNotOptedIn = bind.notOptedIn
	pr.kv(scopeLabel(bind.name), fmt.Sprintf("%d collectable · %d discovered · %d not-collectable",
		len(bind.collectable), bind.discovered, bind.notOptedIn))
	collectable := bind.collectable
	scopes := bind.scopes

	// Default output: ./output/<engagement>/ in the current working directory, one
	// folder per engagement (provider-account-timestamp). An explicit --out is used
	// verbatim (so --resume can point back at a prior engagement dir).
	if opts.Out == "" {
		opts.Out = filepath.Join("output", fmt.Sprintf("thunderstorm-%s-%s-%s",
			bind.name, bind.account, started.Format("20060102T150405Z")))
	}

	// --- 3. Create the Evidence Bundle. ---
	bundleDir := filepath.Join(opts.Out, "full")
	b, err := output.New(bundleDir, !opts.Resume)
	if err != nil {
		return nil, fmt.Errorf("creating bundle: %w", err)
	}
	bind.setBlobDir(filepath.Join(bundleDir, "blobs"))

	// --- 5. Load registry, validate ops, run the Collection DAG. ---
	reg, err := registry.Load(bind.name)
	if err != nil {
		return nil, fmt.Errorf("loading registry: %w", err)
	}
	var usable []registry.ResourceType
	var skippedOps []string
	for _, rt := range reg.Resources {
		if !bind.hasOp(rt.Enumerate.Operation) {
			skippedOps = append(skippedOps, rt.Enumerate.Operation)
			continue
		}
		usable = append(usable, rt)
	}
	reg.Resources = usable
	stats.ResourceTypes = len(reg.Resources)
	stats.SkippedOps = len(skippedOps)
	requiredPerms := reg.RequiredPermissions()
	regNote := fmt.Sprintf("%d resource types", len(reg.Resources))
	if len(skippedOps) > 0 {
		regNote += fmt.Sprintf(" · %d ops unimplemented", len(skippedOps))
	}
	pr.kv("registry", regNote)

	seeds := planner.Seed(reg, bind.account, collectable, bind.globalCall)

	if opts.Resume {
		prior, err := ledger.LoadCoverage(filepath.Join(bundleDir, "ledger", "coverage.ndjson"))
		if err != nil {
			pr.vprintf(opts.Verbose, "resume: no prior coverage (%v) — running fresh\n", err)
		} else {
			p := ledger.NewPrior(prior)
			var todo []scheduler.Task
			skipped := 0
			for _, t := range seeds {
				if p.Done(t.ID) {
					led.Resumed(t.ID, t.Scope, t.Res.ResourceType, t.Op)
					skipped++
					continue
				}
				todo = append(todo, t)
			}
			pr.kv("resume", fmt.Sprintf("%d already done · %d to re-run", skipped, len(todo)))
			seeds = todo
		}
	}

	t0 := time.Now()
	sched := scheduler.New(bind.cli, bind.classify, led, b, opts.Concurrency)
	if opts.Debug {
		sched.SetDebug(os.Stderr)
	}
	// Live progress: the seed count (one enumerate per resource-type × scope) is a
	// known, monotonic denominator, so the percentage is real — never estimated.
	bar := pr.bar("collect", len(seeds), func() progress.Snapshot {
		s := sched.Snapshot()
		note := fmt.Sprintf("%s artifacts", comma(s.Artifacts))
		if s.Denied > 0 {
			note += fmt.Sprintf(" · %s denied", comma(s.Denied))
		}
		if s.Throttled > 0 {
			note += fmt.Sprintf(" · %s throttled", comma(s.Throttled))
		}
		if s.Errored > 0 {
			note += fmt.Sprintf(" · %s errored", comma(s.Errored))
		}
		return progress.Snapshot{Done: s.SeedsDone, Total: len(seeds), Note: note}
	})
	// Verbose: stream a line the first time each resource type begins collecting,
	// printed above the live bar.
	if opts.Verbose && bar.b != nil {
		sched.SetOnClusterStart(func(rt string) { bar.b.Log("  → " + rt) })
	}
	nArtifacts := sched.Run(ctx, seeds)
	bar.stop()
	stats.SeedTasks, stats.Artifacts, stats.CollectDur = len(seeds), nArtifacts, time.Since(t0)
	snap := sched.Snapshot()
	pr.phase("collect", fmt.Sprintf("%s artifacts · %s ops", comma(nArtifacts), comma(len(seeds))), stats.CollectDur)
	if opts.Verbose {
		pr.vprintf(true, "               %s ok · %s empty · %s denied · %s throttled · %s errored · %s detail calls\n",
			comma(snap.OK), comma(snap.Empty), comma(snap.Denied), comma(snap.Throttled), comma(snap.Errored), comma(snap.Detail))
		pr.serviceBreakdown(led.Rows())
	}

	// --- Exposure prober over the read_api catalog. ---
	sites, err := exposure.LoadCatalog(bind.name)
	if err != nil {
		return nil, fmt.Errorf("loading exposure catalog: %w", err)
	}
	salt := bind.account + "|" + started.Format(time.RFC3339)
	t0 = time.Now()
	prober := exposure.NewProber(bind.fetchers, bind.listFetchers, collectable, bind.classify, led, b, bundleDir, salt, bind.account, opts.Concurrency)
	prober.SetTotal(len(sites))
	if opts.Debug {
		prober.SetDebug(os.Stderr)
	}
	ebar := pr.bar("exposure", len(sites), func() progress.Snapshot {
		s := prober.Snapshot()
		note := fmt.Sprintf("%s hits", comma(s.Hits))
		return progress.Snapshot{Done: s.SitesDone, Total: s.Total, Note: note}
	})
	es := prober.Run(ctx, sites)
	ebar.stop()
	stats.ExposureTotal, stats.ExposureReadAPI, stats.ExposureSurfaces = es.Total, es.ReadAPI, es.Surfaces
	stats.ExposureProbed, stats.ExposureHits, stats.ExposureDur = es.Probed, es.Hits, time.Since(t0)
	pr.phase("exposure", fmt.Sprintf("%s hits · %s probed · %s sites", comma(es.Hits), comma(es.Probed), comma(es.Total)), stats.ExposureDur)
	if opts.Verbose {
		pr.vprintf(true, "               %s read_api · %s surfaces · %s no-probe · %s no-inventory · %s denied\n",
			comma(es.ReadAPI), comma(es.Surfaces), comma(es.SkippedNoProbe), comma(es.SkippedNoInventory), comma(es.Denied))
	}

	// --- Facts tier: policy/trust/network facts -> graph EDGES. ---
	t0 = time.Now()
	nFacts := 0
	if bind.collectFacts != nil {
		// Facts have no upfront total (each provider fans out its own tasks), so
		// this is a spinner with elapsed rather than a percentage bar.
		fbar := pr.bar("facts", 0, func() progress.Snapshot {
			return progress.Snapshot{Note: "collecting policy · trust · network facts"}
		})
		nFacts = bind.collectFacts(ctx, led, b, opts.Concurrency)
		fbar.stop()
	}
	stats.Facts, stats.FactsDur = nFacts, time.Since(t0)
	pr.phase("facts", fmt.Sprintf("%s facts", comma(nFacts)), stats.FactsDur)

	deniedPerms := deniedPermissions(led.Rows())

	// --- 6. Finalize the bundle. ---
	var cov strings.Builder
	for _, row := range led.Rows() {
		line, _ := json.Marshal(row)
		cov.Write(line)
		cov.WriteByte('\n')
	}
	_ = b.WriteFile("ledger/coverage.ndjson", []byte(cov.String()))
	report := led.Report(bind.name, bind.account, scopes,
		ledger.ReportOpts{RequiredPermissions: requiredPerms, DeniedPermissions: deniedPerms})
	_ = b.WriteFile("ledger/report.md", []byte(report))

	m := model.Manifest{
		Version:     version.Block(contract, components),
		Provider:    bind.name,
		Account:     bind.account,
		CallerARN:   bind.caller,
		StartedAt:   started,
		EndedAt:     time.Now().UTC(),
		Scopes:      scopes,
		Summary:     led.Summary(),
		IntegrityOK: led.IntegrityOK(),
	}
	if err := b.WriteManifest(m); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}
	if err := b.Close(); err != nil {
		return nil, fmt.Errorf("closing bundle: %w", err)
	}

	zipPath := filepath.Join(opts.Out, fmt.Sprintf("thunderstorm-%s-%s-%s.zip",
		bind.name, bind.account, started.Format("20060102T150405Z")))
	if _, err := b.Zip(zipPath, opts.IncludeBlobs); err != nil {
		return nil, fmt.Errorf("zipping bundle: %w", err)
	}

	return &Result{
		BundleDir:   bundleDir,
		ExposureDir: filepath.Join(bundleDir, "exposure"),
		Account:     bind.account,
		Provider:    bind.name,
		ZipPath:     zipPath,
		Report:      report,
		IntegrityOK: m.IntegrityOK,
		Manifest:    m,
		Stats:       stats,
	}, nil
}

// scopeLabel is the console word for a provider's collectable scope units.
func scopeLabel(provider string) string {
	if provider == "gcp" {
		return "locations"
	}
	return "regions"
}

// --- console formatting: aligned key/value + phase lines, shared with the CLI ---

// LabelWidth is the column width for aligned "label  value" console output.
const LabelWidth = 12

// printer gates a run's console output. In parallel multi-scope runs it is quiet so
// concurrent scopes don't interleave; the orchestrator prints a concise per-scope line.
type printer struct {
	quiet   bool
	verbose bool
}

// kv prints an aligned "  label   value" metadata line.
func (p printer) kv(label, value string) {
	if p.quiet {
		return
	}
	fmt.Printf("  %-*s %s\n", LabelWidth, label, value)
}

// phase prints an aligned metadata line with a right-hand elapsed time.
func (p printer) phase(label, value string, d time.Duration) {
	if p.quiet {
		return
	}
	fmt.Printf("  %-*s %-46s %s\n", LabelWidth, label, value, FmtDur(d))
}

// vprintf prints only when verbose is set (and not quiet).
func (p printer) vprintf(verbose bool, format string, a ...any) {
	if p.quiet || !verbose {
		return
	}
	fmt.Printf(format, a...)
}

// phaseBar is a running progress bar handle; stop() erases the live line so the
// caller's permanent phase() summary line takes its place. In quiet mode it is a
// no-op (multi-scope parallel runs render one line per scope instead).
type phaseBar struct{ b *progress.Bar }

func (h phaseBar) stop() {
	if h.b != nil {
		h.b.Stop()
	}
}

// bar starts a live progress bar for a phase (unless quiet). total<=0 renders a
// spinner (indeterminate work).
func (p printer) bar(label string, total int, poll func() progress.Snapshot) phaseBar {
	if p.quiet {
		return phaseBar{}
	}
	b := progress.New(os.Stdout, label, LabelWidth, poll)
	b.Start()
	return phaseBar{b: b}
}

// serviceBreakdown prints the top collected services by resource count (verbose).
func (p printer) serviceBreakdown(rows []model.LedgerRow) {
	if p.quiet {
		return
	}
	counts := map[string]int{}
	for _, r := range rows {
		if r.Status != model.OutcomeOK || r.Count == 0 {
			continue
		}
		parts := strings.Split(r.ResourceType, ":")
		if len(parts) >= 2 && parts[0] != "exposure" && !strings.HasSuffix(r.ResourceType, ":scope") {
			counts[parts[1]] += r.Count
		}
	}
	if len(counts) == 0 {
		return
	}
	type kv struct {
		svc string
		n   int
	}
	list := make([]kv, 0, len(counts))
	for s, n := range counts {
		list = append(list, kv{s, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].svc < list[j].svc
	})
	top := list
	if len(top) > 15 {
		top = top[:15]
	}
	parts := make([]string, 0, len(top))
	for _, e := range top {
		parts = append(parts, fmt.Sprintf("%s %s", e.svc, comma(e.n)))
	}
	fmt.Printf("               top services: %s", strings.Join(parts, " · "))
	if len(list) > len(top) {
		fmt.Printf(" · (+%d more)", len(list)-len(top))
	}
	fmt.Println()
}

// comma renders an int with thousands separators (e.g. 60861 -> "60,861").
func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteByte(s[i])
	}
	if neg {
		return "-" + out.String()
	}
	return out.String()
}

// FmtDur renders a duration compactly: sub-minute to 0.1s, else whole seconds.
func FmtDur(d time.Duration) string {
	if d < time.Minute {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}
