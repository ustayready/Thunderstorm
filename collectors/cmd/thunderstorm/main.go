// Command thunderstorm is the single, self-contained Thunderstorm binary. It
// scans a cloud environment (read-only), builds the attack-path graph, and writes
// ONE RAGE engagement.zip that Blaze ingests. Gather and generate — nothing else.
//
//	thunderstorm scan   --profile <p> [--provider aws] [--only-regions a,b] [--out <dir|.zip>]
//	thunderstorm redact --in <engagement.zip> --out <path>
//	thunderstorm view   [--in <engagement.zip|.ndjson>]
//	thunderstorm version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	engrun "thunderstorm/engine/run"

	assets "thunderstorm/collector"
	"thunderstorm/collector/internal/rageexport"
	"thunderstorm/collector/internal/redact"
	"thunderstorm/collector/internal/run"
	"thunderstorm/collector/internal/version"
	"thunderstorm/collector/internal/view"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "redact":
		cmdRedact(os.Args[2:])
	case "view":
		cmdView(os.Args[2:])
	case "version":
		fmt.Printf("thunderstorm %s / engine %s / RAGE %s (supports catalog %s, bundle schema %s)\n",
			version.CollectorVersion, engrun.Version, assets.RageVersion(), version.SupportedRange(), version.BundleSchemaVersion)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `thunderstorm — gather a cloud environment and generate its RAGE attack-path graph

  scan     --profile <p> [--provider aws] [--region r] [--only-regions a,b] [--out <dir|.zip>]
           Collect (read-only) + build the attack-path graph + write ONE RAGE engagement.zip.
           Default output: ./output/thunderstorm-<provider>-<account>-<ts>.zip
           -v/--verbose  richer per-phase detail (per-service breakdown, outcome counts)
           --debug       stream every API call in/out/error to stderr (implies --verbose)
           Long scans survive terminal hangup (SIGHUP ignored); Ctrl-C stops cleanly.
  redact   --in <engagement.zip> --out <path> [--audit <path>]
           Rewrite an engagement into a de-identified, graph-isomorphic copy.
  view     [--in <engagement.zip|.ndjson>]
           Open Blaze Lite (the embedded, offline attack-path viewer) in the
           browser. With --in the engagement is loaded automatically; without it
           the viewer opens ready for a drag-and-drop.
  version

  --out accepts a .zip file path or a directory (a filename is generated inside a directory).
`)
}

// collectFlags registers the shared collector flags on fs.
func collectFlags(fs *flag.FlagSet) *run.Options {
	o := &run.Options{}
	fs.StringVar(&o.Profile, "profile", "", "AWS shared-config profile (default: SDK chain)")
	fs.StringVar(&o.Provider, "provider", "aws", "cloud provider (aws|gcp|azure)")
	fs.StringVar(&o.Project, "project", "", "GCP project id (required for --provider gcp)")
	fs.StringVar(&o.ImpersonateSA, "impersonate-sa", "", "GCP service account to impersonate for the run (optional)")
	fs.StringVar(&o.Subscription, "subscription", "", "Azure subscription id to limit collection (default: all accessible)")
	fs.StringVar(&o.BootstrapRegion, "region", "us-east-1", "AWS bootstrap region")
	fs.StringVar(&o.OnlyRegions, "only-regions", "", "comma-separated regions/locations to limit collection")
	fs.StringVar(&o.RepoRoot, "repo-root", "", "repo root (auto-detected if empty)")
	fs.IntVar(&o.Concurrency, "concurrency", 24, "max concurrent operations (per phase; raise for large accounts, lower if throttled)")
	fs.BoolVar(&o.IncludeBlobs, "include-blobs", false, "include raw blobs in the bundle zip")
	fs.BoolVar(&o.Resume, "resume", false, "resume a prior bundle at the work dir")
	fs.BoolVar(&o.Verbose, "verbose", false, "print per-operation detail (default: concise summary)")
	fs.BoolVar(&o.Verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&o.Debug, "debug", false, "stream every API call in/out/error to stderr (implies --verbose)")
	return o
}

// runContext returns a context wired for long, unattended scans:
//   - SIGHUP is IGNORED so a dropped SSH/terminal session never kills a run that
//     may take far longer than the session stays up (the reported failure mode).
//   - SIGINT/SIGTERM cancel the context so in-flight work stops and the workdir is
//     preserved; a second interrupt force-quits.
func runContext() context.Context {
	signal.Ignore(syscall.SIGHUP)
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		fmt.Fprintln(os.Stderr, "\ninterrupt — stopping in-flight work and keeping the workdir (Ctrl-C again to force-quit)")
		cancel()
		<-ch
		fmt.Fprintln(os.Stderr, "forced quit")
		os.Exit(130)
	}()
	return ctx
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	opts := collectFlags(fs)
	out := fs.String("out", "", "output engagement.zip path or directory (default: ./output/)")
	workDir := fs.String("workdir", "", "scratch dir for the bundle+graph (default: temp, removed after)")
	keep := fs.Bool("keep-workdir", false, "keep the scratch dir instead of removing it")
	scopesFile := fs.String("scopes", "", "multi-scope: path to a `provider:scope` file (one per line)")
	awsProfiles := fs.String("aws-profiles", "", "multi-scope: AWS profiles (file path or csv)")
	gcpProjects := fs.String("gcp-projects", "", "multi-scope: GCP project ids (file path or csv)")
	azureSubs := fs.String("azure-subscriptions", "", "multi-scope: Azure subscription ids (file path or csv)")
	maxScopes := fs.Int("max-scopes", 0, "multi-scope: abort discovery if it exceeds N scopes (0 = unlimited)")
	scopeConc := fs.Int("scope-concurrency", 1, "multi-scope: how many scopes to collect in parallel (raise for many projects)")
	_ = fs.Parse(args)
	opts.ScopeConcurrency = *scopeConc

	sel := run.Selector{ScopesFile: *scopesFile, AWSProfiles: *awsProfiles, GCPProjects: *gcpProjects, AzureSubs: *azureSubs, MaxScopes: *maxScopes}
	// Multi-scope when any scope flag is supplied, or when GCP is asked for with no
	// project (the discovery default). Everything else keeps the single-scope path.
	if sel.Explicit() || (opts.Provider == "gcp" && opts.Project == "") {
		cmdScanMulti(fs, opts, sel, *out, *workDir, *keep)
		return
	}

	// scratch dir for bundle + graph. Kept on failure so a run is never lost.
	work := *workDir
	if work == "" {
		var err error
		work, err = os.MkdirTemp("", "thunderstorm-scan-")
		must(err)
	}
	graphDir := filepath.Join(work, "graph")

	start := time.Now()
	printHeader("scan", start)
	failWorkdir := func(err error) {
		fmt.Fprintf(os.Stderr, "\nerror: %v\nworkdir kept at %s\n", err, work)
		os.Exit(1)
	}

	opts.Out = filepath.Join(work, "bundle")
	res, err := run.Collect(runContext(), *opts)
	if err != nil {
		failWorkdir(err)
	}

	at := time.Now().UTC()
	t0 := time.Now()
	man, _, err := engrun.BuildGraph(res.BundleDir, graphDir, at)
	if err != nil {
		failWorkdir(err)
	}
	printPhase("graph", fmt.Sprintf("%d nodes · %d edges · %d paths",
		man.Counts["nodes"], man.Counts["edges"], man.Counts["paths"]), time.Since(t0))

	// Generate the RAGE engagement.zip (graph.rage.ndjson with real evidence).
	t0 = time.Now()
	outZip := resolveScanOut(*out, res.Provider, res.Account, at)
	st, err := rageexport.RunWorkdir(work, outZip)
	if err != nil {
		failWorkdir(err)
	}
	if !*keep {
		os.RemoveAll(work)
	}
	printPhase("rage", fmt.Sprintf("%d nodes · %d edges · %d findings · %d surfaces",
		st.Nodes, st.Edges, st.Findings, st.Surfaces), time.Since(t0))

	fmt.Println()
	printKV("engagement", outZip)
	printKV("provider", res.Provider)
	printKV("account", res.Account)
	printKV("size", humanBytes(fileSize(outZip)))
	printKV("finished", at.Format("2006-01-02 15:04:05 MST"))
	printKV("elapsed", run.FmtDur(time.Since(start)))
	fmt.Println("\n  → upload this into Blaze")
}

// cmdScanMulti runs the collector over a LIST of scopes, merges every scope's bundle
// into one full/ tree, builds ONE graph over the union, and writes a single RAGE
// engagement.zip.
func cmdScanMulti(fs *flag.FlagSet, opts *run.Options, sel run.Selector, out, workDir string, keep bool) {
	ctx := runContext()
	work := workDir
	if work == "" {
		var err error
		work, err = os.MkdirTemp("", "thunderstorm-scan-")
		must(err)
	}
	graphDir := filepath.Join(work, "graph")
	start := time.Now()
	printHeader("scan (multi-scope)", start)
	failWorkdir := func(err error) {
		fmt.Fprintf(os.Stderr, "\nerror: %v\nworkdir kept at %s\n", err, work)
		os.Exit(1)
	}

	scopes, mode, err := run.ResolveScopes(ctx, *opts, sel)
	if err != nil {
		failWorkdir(err)
	}
	if len(scopes) == 0 {
		failWorkdir(fmt.Errorf("no scopes resolved (check --scopes / per-provider flags or credentials)"))
	}
	if sel.MaxScopes > 0 && len(scopes) > sel.MaxScopes {
		failWorkdir(fmt.Errorf("resolved %d scopes, exceeds --max-scopes %d", len(scopes), sel.MaxScopes))
	}
	printKV("scopes", fmt.Sprintf("%d (%s)", len(scopes), mode))

	results := run.CollectScopes(ctx, *opts, scopes, work)
	okCount := 0
	for _, r := range results {
		if r.Status == "ok" {
			okCount++
		}
	}
	if okCount == 0 {
		failWorkdir(fmt.Errorf("every scope failed to collect"))
	}

	// Merge into work/bundle/full so the RAGE exporter (which reads wd/bundle/full)
	// sees the union of every scope's evidence.
	bundleFull := filepath.Join(work, "bundle", "full")
	if err := run.MergeBundles(results, bundleFull); err != nil {
		failWorkdir(err)
	}

	at := time.Now().UTC()
	t0 := time.Now()
	man, _, err := engrun.BuildGraph(bundleFull, graphDir, at)
	if err != nil {
		failWorkdir(err)
	}
	printPhase("graph", fmt.Sprintf("%d nodes · %d edges · %d paths",
		man.Counts["nodes"], man.Counts["edges"], man.Counts["paths"]), time.Since(t0))

	t0 = time.Now()
	outZip := resolveScanOut(out, "multi", "multi", at)
	st, err := rageexport.RunWorkdir(work, outZip)
	if err != nil {
		failWorkdir(err)
	}
	if !keep {
		os.RemoveAll(work)
	}
	printPhase("rage", fmt.Sprintf("%d nodes · %d edges · %d findings · %d surfaces",
		st.Nodes, st.Edges, st.Findings, st.Surfaces), time.Since(t0))

	fmt.Println()
	printKV("engagement", outZip)
	printKV("scopes", fmt.Sprintf("%d ok · %d failed", okCount, len(results)-okCount))
	printKV("size", humanBytes(fileSize(outZip)))
	printKV("finished", at.Format("2006-01-02 15:04:05 MST"))
	printKV("elapsed", run.FmtDur(time.Since(start)))
	fmt.Println("\n  → upload this into Blaze")
}

// cmdRedact rewrites an engagement.zip into a graph-isomorphic, de-identified copy:
// every org identifier becomes an opaque, irreversible synthetic value, while nodes,
// edges, and paths keep their structure. Fully offline; fail-closed (a surviving real
// identifier or a structural mismatch quarantines the output).
func cmdRedact(args []string) {
	fs := flag.NewFlagSet("redact", flag.ExitOnError)
	in := fs.String("in", "", "input engagement.zip to redact")
	out := fs.String("out", "", "output (redacted) engagement.zip path")
	audit := fs.String("audit", "", "optional path to write the JSON audit report")
	_ = fs.Parse(args)
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "redact: --in <engagement.zip> and --out <path> are required")
		os.Exit(2)
	}
	report, err := redact.Run(*in, *out, redact.Options{AuditPath: *audit})
	if report != nil {
		printKV("real tokens", fmt.Sprintf("%d scanned", report.RealTokens))
		printKV("synthetic blobs", fmt.Sprintf("%d", report.SyntheticBlob))
		if len(report.DroppedFiles) > 0 {
			printKV("dropped", strings.Join(report.DroppedFiles, ", "))
		}
	}
	if err != nil {
		must(err)
	}
	printKV("audit", "PASS — no real identifiers survived; graph structure preserved")
	printKV("out", *out)
}

// cmdView opens Blaze Lite (the embedded, offline attack-path viewer) in the
// browser. With --in the engagement.zip/.ndjson is injected and auto-loaded;
// without it the viewer opens ready for a drag-and-drop.
func cmdView(args []string) {
	fs := flag.NewFlagSet("view", flag.ExitOnError)
	in := fs.String("in", "", "engagement.zip or .ndjson to open (optional)")
	_ = fs.Parse(args)
	if err := view.Run(*in); err != nil {
		must(err)
	}
}

// resolveScanOut turns --out into a concrete .zip path (defaulting to ./output/) and
// ensures the containing directory exists.
func resolveScanOut(out, provider, account string, at time.Time) string {
	if out == "" {
		out = "output"
	}
	// No .zip suffix → treat as a directory to drop a generated filename into.
	if !strings.HasSuffix(strings.ToLower(out), ".zip") {
		must(os.MkdirAll(out, 0o755))
	}
	zipPath := resolveOutZip(out, provider, account, at)
	must(os.MkdirAll(filepath.Dir(zipPath), 0o755))
	return zipPath
}

// resolveOutZip turns a user --out into a concrete .zip path. A directory (or a
// path ending in /) gets a generated filename inside it; a bare name gets .zip.
func resolveOutZip(out, provider, account string, at time.Time) string {
	info, err := os.Stat(out)
	if (err == nil && info.IsDir()) || strings.HasSuffix(out, string(os.PathSeparator)) {
		return filepath.Join(out, fmt.Sprintf("thunderstorm-%s-%s-%s.zip",
			provider, account, at.Format("20060102T150405Z")))
	}
	if !strings.HasSuffix(strings.ToLower(out), ".zip") {
		return out + ".zip"
	}
	return out
}

// printHeader prints the run banner: command, timestamp, and versions.
func printHeader(cmd string, at time.Time) {
	fmt.Printf("thunderstorm %s · %s\n", cmd, at.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("collector %s · engine %s · RAGE %s\n\n", version.CollectorVersion, engrun.Version, assets.RageVersion())
}

func printKV(label, value string) { fmt.Printf("  %-*s %s\n", run.LabelWidth, label, value) }
func printPhase(label, value string, d time.Duration) {
	fmt.Printf("  %-*s %-46s %s\n", run.LabelWidth, label, value, run.FmtDur(d))
}

func fileSize(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

// humanBytes renders a byte count as B/KB/MB/GB with one decimal.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
