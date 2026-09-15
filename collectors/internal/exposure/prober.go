package exposure

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
	"sync/atomic"
	"time"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
)

// Fetcher fetches the raw (jsonified) API response for one inventory item, so
// the prober can apply each site's response_path to it. ResourceType names the
// inventory to iterate; item carries {native_id, arn, ...attributes}.
type Fetcher struct {
	ResourceType string
	Fetch        func(ctx context.Context, region string, item map[string]any) (any, error)
}

// FetcherSet maps a site's read.operation → its Fetcher.
type FetcherSet map[string]Fetcher

// ListFetcher is a SELF-ENUMERATING fetcher for sites whose target sub-resources
// aren't in inventory (findings, dashboards, health checks, ...). It lists its
// own targets per region and returns 0..N jsonified responses; the prober
// applies the site's response_path to each.
type ListFetcher struct {
	Fetch func(ctx context.Context, region string) ([]any, error)
}

// ListFetcherSet maps a site's read.operation → its self-enumerating fetcher.
type ListFetcherSet map[string]ListFetcher

// Classifier maps an error to "denied" | "throttled" | "error".
type Classifier func(error) string

// Summary reconciles a prober run against the whole catalog.
type Summary struct {
	Total, ReadAPI, Surfaces int
	Probed, Hits             int
	SkippedNoProbe           int
	SkippedNoInventory       int
	Denied, Errored          int
}

// Prober runs read_api sites against collected inventory. It is structurally
// incapable of invoking a non-read_api recipe: those never reach a fetcher.
type Prober struct {
	fetchers     FetcherSet
	listFetchers ListFetcherSet
	regions      []string
	classify     Classifier
	led          *ledger.Ledger
	bundle       *output.Bundle
	dir          string
	salt         string
	account      string

	concurrency int

	cacheMu  sync.Mutex
	invCache map[string][]model.Artifact // resourceType -> artifacts
	fetch    map[string]any              // (op|region|id) -> response
	fetchErr map[string]error

	// Live counters (atomic) for a progress renderer that polls Snapshot.
	sitesDone atomic.Int64
	hitsC     atomic.Int64
	total     int
	debug     io.Writer // non-nil in --debug: per-fetch in/out/error → stderr
}

// SetDebug enables per-fetch in/out/error logging to w (typically stderr).
func (p *Prober) SetDebug(w io.Writer) { p.debug = w }

// SetTotal records the site count so Snapshot can report an accurate percentage.
func (p *Prober) SetTotal(n int) { p.total = n }

// ProbeProgress is a lock-free live snapshot of the exposure phase.
type ProbeProgress struct {
	SitesDone int
	Total     int
	Hits      int
}

// Snapshot returns the current exposure counters for a live progress renderer.
func (p *Prober) Snapshot() ProbeProgress {
	return ProbeProgress{
		SitesDone: int(p.sitesDone.Load()),
		Total:     p.total,
		Hits:      int(p.hitsC.Load()),
	}
}

func NewProber(fetchers FetcherSet, listFetchers ListFetcherSet, regions []string, classify Classifier,
	led *ledger.Ledger, b *output.Bundle, bundleDir, salt, account string, concurrency int) *Prober {
	if concurrency < 1 {
		concurrency = 12
	}
	return &Prober{fetchers: fetchers, listFetchers: listFetchers, regions: regions,
		classify: classify, led: led, bundle: b, dir: bundleDir,
		salt: salt, account: account, concurrency: concurrency,
		invCache: map[string][]model.Artifact{},
		fetch:    map[string]any{}, fetchErr: map[string]error{}}
}

// Run probes every site and returns the reconciliation summary. Sites are probed
// concurrently (bounded by p.concurrency); the shared caches and summary are
// mutex-guarded. This phase used to run strictly one site at a time — the biggest
// serial cost on large accounts after the facts phase.
func (p *Prober) Run(ctx context.Context, sites []Site) Summary {
	p.total = len(sites)
	sum := Summary{Total: len(sites)}
	var sumMu sync.Mutex
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	for _, s := range sites {
		s := s
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			p.probeSite(ctx, s, &sum, &sumMu)
		}()
	}
	wg.Wait()
	return sum
}

// probeSite probes one site and folds its outcome into sum (under sumMu).
func (p *Prober) probeSite(ctx context.Context, s Site, sum *Summary, sumMu *sync.Mutex) {
	defer p.sitesDone.Add(1)
	add := func(f func(*Summary)) { sumMu.Lock(); f(sum); sumMu.Unlock() }

	task := "exposure/" + s.ID
	scope := model.Scope{Provider: "aws", Account: p.account}
	p.led.Plan(task, scope, "exposure:"+s.Service, s.Read.Operation)

	// SAFETY GATE: non-read_api sites are surfaces — recorded, never invoked.
	if !s.IsReadAPI() {
		add(func(sm *Summary) { sm.Surfaces++ })
		_ = p.bundle.AppendJSON("exposure/surfaces.ndjson", model.Surface{
			SiteID: s.ID, AccessMode: s.Read.AccessMode, Location: s.Location,
			EmitsHint: s.EmitsHint, Severity: s.Severity,
		})
		p.led.Finish(task, model.OutcomeSkipped, 0, "surface:"+s.Read.AccessMode)
		return
	}
	add(func(sm *Summary) { sm.ReadAPI++ })

	f, ok := p.fetchers[s.Read.Operation]
	if !ok {
		if lf, ok2 := p.listFetchers[s.Read.Operation]; ok2 {
			p.runListFetcher(ctx, task, s, lf, sum, sumMu)
			return
		}
		add(func(sm *Summary) { sm.SkippedNoProbe++ })
		p.led.Finish(task, model.OutcomeSkipped, 0, "no_probe_impl")
		return
	}
	arts := p.inventory(f.ResourceType)
	if len(arts) == 0 {
		add(func(sm *Summary) { sm.SkippedNoInventory++ })
		p.led.Finish(task, model.OutcomeSkipped, 0, "no_inventory_targets")
		return
	}

	p.led.Start(task)
	hits := 0
	var failed error
	for _, art := range arts {
		resp, err := p.cachedFetch(ctx, f, s.Read.Operation, art)
		if err != nil {
			failed = err
			continue
		}
		for _, val := range Extract(resp, s.Read.ResponsePath) {
			if hit, conf := Assess(val, s.LocationKind); hit {
				hits++
				_ = p.bundle.AppendJSON("exposure/hits.ndjson", hitRecord(s, art, val, conf, p.salt))
			}
		}
	}
	add(func(sm *Summary) { sm.Probed++ })
	switch {
	case failed != nil && hits == 0:
		switch p.classify(failed) {
		case "denied":
			add(func(sm *Summary) { sm.Denied++ })
			p.led.Finish(task, model.OutcomeDenied, 0, shortErr(failed))
		case "throttled":
			p.led.Finish(task, model.OutcomeThrottled, 0, shortErr(failed))
		default:
			add(func(sm *Summary) { sm.Errored++ })
			p.led.Finish(task, model.OutcomeError, 0, shortErr(failed))
		}
	case hits > 0:
		add(func(sm *Summary) { sm.Hits += hits })
		p.hitsC.Add(int64(hits))
		p.led.Finish(task, model.OutcomeOK, hits, "")
	default:
		p.led.Finish(task, model.OutcomeEmpty, 0, "")
	}
}

// runListFetcher probes a self-enumerating site: per region the fetcher lists
// its own targets and returns 0..N responses; response_path is applied to each.
func (p *Prober) runListFetcher(ctx context.Context, task string, s Site, lf ListFetcher, sum *Summary, sumMu *sync.Mutex) {
	add := func(f func(*Summary)) { sumMu.Lock(); f(sum); sumMu.Unlock() }
	p.led.Start(task)
	hits := 0
	var failed error
	for _, region := range p.regions {
		key := s.Read.Operation + "|list|" + region
		raw, err := p.cachedListFetch(ctx, lf, key, region)
		if err != nil {
			failed = err
			continue
		}
		resps, _ := raw.([]any)
		for _, resp := range resps {
			for _, val := range Extract(resp, s.Read.ResponsePath) {
				if hit, _ := Assess(val, s.LocationKind); hit {
					hits++
					_ = p.bundle.AppendJSON("exposure/hits.ndjson", model.ExposureHit{
						SiteID: s.ID, ResourceID: "(self-enumerated)", Provider: "aws",
						Scope:     model.Scope{Provider: "aws", Account: p.account, Region: region},
						EmitsHint: s.EmitsHint, Severity: s.Severity, Location: s.Location,
						Found: true, ValueRef: Redact(val, p.salt), Value: CapValue(val),
					})
				}
			}
		}
	}
	add(func(sm *Summary) { sm.Probed++ })
	switch {
	case failed != nil && hits == 0:
		switch p.classify(failed) {
		case "denied":
			add(func(sm *Summary) { sm.Denied++ })
			p.led.Finish(task, model.OutcomeDenied, 0, shortErr(failed))
		case "throttled":
			p.led.Finish(task, model.OutcomeThrottled, 0, shortErr(failed))
		default:
			add(func(sm *Summary) { sm.Errored++ })
			p.led.Finish(task, model.OutcomeError, 0, shortErr(failed))
		}
	case hits > 0:
		add(func(sm *Summary) { sm.Hits += hits })
		p.hitsC.Add(int64(hits))
		p.led.Finish(task, model.OutcomeOK, hits, "")
	default:
		p.led.Finish(task, model.OutcomeEmpty, 0, "")
	}
}

// cachedFetch fetches (once) the response for an (operation, item) pair; sites
// sharing an operation over the same item reuse it. Safe for concurrent callers:
// a cache miss may fetch redundantly under rare races, but map access is guarded.
func (p *Prober) cachedFetch(ctx context.Context, f Fetcher, op string, art model.Artifact) (any, error) {
	key := op + "|" + art.Scope.Region + "|" + art.NativeID
	p.cacheMu.Lock()
	if v, ok := p.fetch[key]; ok {
		err := p.fetchErr[key]
		p.cacheMu.Unlock()
		return v, err
	}
	p.cacheMu.Unlock()

	item := map[string]any{"native_id": art.NativeID, "arn": art.ARN}
	for k, v := range art.Attributes {
		item[k] = v
	}
	t0 := time.Now()
	resp, err := f.Fetch(ctx, art.Scope.Region, item)
	p.logFetch(op, art.Scope.Region, art.NativeID, time.Since(t0), err)

	p.cacheMu.Lock()
	p.fetch[key] = resp
	p.fetchErr[key] = err
	p.cacheMu.Unlock()
	return resp, err
}

// logFetch writes one in/out/error debug line for an exposure probe fetch.
func (p *Prober) logFetch(op, region, target string, dur time.Duration, err error) {
	if p.debug == nil {
		return
	}
	if region == "" {
		region = "-"
	}
	if err != nil {
		fmt.Fprintf(p.debug, "[debug] probe %s region=%s target=%s → ERROR %s: %s (%s)\n",
			op, region, target, p.classify(err), shortErr(err), fmtDur(dur))
		return
	}
	fmt.Fprintf(p.debug, "[debug] probe %s region=%s target=%s → ok (%s)\n",
		op, region, target, fmtDur(dur))
}

// cachedListFetch is the self-enumerating analogue of cachedFetch, keyed per
// (operation,region). Concurrency-safe with the same rare-redundant-fetch caveat.
func (p *Prober) cachedListFetch(ctx context.Context, lf ListFetcher, key, region string) (any, error) {
	p.cacheMu.Lock()
	if v, seen := p.fetch[key]; seen {
		err := p.fetchErr[key]
		p.cacheMu.Unlock()
		return v, err
	}
	p.cacheMu.Unlock()

	t0 := time.Now()
	r, err := lf.Fetch(ctx, region)
	p.logFetch(key, region, "(self-enumerated)", time.Since(t0), err)

	p.cacheMu.Lock()
	p.fetch[key] = r
	p.fetchErr[key] = err
	p.cacheMu.Unlock()
	return r, err
}

func hitRecord(s Site, art model.Artifact, val string, conf float64, salt string) model.ExposureHit {
	_ = conf
	return model.ExposureHit{
		SiteID: s.ID, ResourceID: art.NativeID, Provider: "aws", Scope: art.Scope,
		EmitsHint: s.EmitsHint, Severity: s.Severity, Location: s.Location,
		Found: true, ValueRef: Redact(val, salt), Value: CapValue(val),
	}
}

func (p *Prober) inventory(resourceType string) []model.Artifact {
	p.cacheMu.Lock()
	if a, ok := p.invCache[resourceType]; ok {
		p.cacheMu.Unlock()
		return a
	}
	p.cacheMu.Unlock()

	path := filepath.Join(p.dir, "inventory", strings.ReplaceAll(resourceType, ":", "-")+".ndjson")
	var arts []model.Artifact
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			var a model.Artifact
			if json.Unmarshal(sc.Bytes(), &a) == nil {
				arts = append(arts, a)
			}
		}
		f.Close()
	}
	p.cacheMu.Lock()
	p.invCache[resourceType] = arts
	p.cacheMu.Unlock()
	return arts
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

// fmtDur renders a duration compactly for debug lines.
func fmtDur(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}
