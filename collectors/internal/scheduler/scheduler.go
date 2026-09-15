// Package scheduler executes the Collection DAG: it runs each resource's
// enumerate call, then fans out per-item detail calls with their bindings
// resolved from the enumerated record. Failures are
// bulkheaded — one task's error never aborts the run; it becomes a ledger row.
package scheduler

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
	"thunderstorm/collector/internal/registry"
)

// Invoker runs a named operation. aws.Client satisfies this.
type Invoker interface {
	Invoke(ctx context.Context, op, region string, params map[string]string) ([]map[string]any, error)
}

// Classifier maps an error to "denied" | "throttled" | "error".
type Classifier func(error) string

// Task is one node in the DAG. step=-1 is the enumerate call; step>=0 indexes
// into the resource's Detail chain. record accumulates yields+captures so later
// bindings and the final artifact can read them.
type Task struct {
	ID         string
	Scope      model.Scope
	CallRegion string // region used for the API call (global ops use a bootstrap region, not "")
	Res        *registry.ResourceType
	Op         string
	Step       int
	Params     map[string]string
	Record     map[string]any
}

type Scheduler struct {
	inv         Invoker
	classify    Classifier
	led         *ledger.Ledger
	bundle      *output.Bundle
	concurrency int

	sem chan struct{}
	wg  sync.WaitGroup

	// Live counters (atomic) so a progress renderer can poll Snapshot lock-free
	// while workers run. seedsDone drives the accurate percentage: the seed total
	// (one enumerate per resource-type × scope) is known before Run starts.
	seedsDone atomic.Int64
	detail    atomic.Int64 // detail (per-item) calls completed
	artifacts atomic.Int64
	okC       atomic.Int64
	emptyC    atomic.Int64
	deniedC   atomic.Int64
	throttleC atomic.Int64
	errC      atomic.Int64
	skippedC  atomic.Int64

	debug io.Writer // non-nil in --debug: log every op in/out/error here (stderr)

	// onClusterStart, if set, fires exactly once per resource type the first time
	// one of its enumerate tasks begins — a streaming "now collecting X" signal.
	onClusterStart func(resourceType string)
	seenMu         sync.Mutex
	seenCluster    map[string]bool
}

// SetOnClusterStart registers a callback fired once per resource type when its
// first enumerate task starts. Safe to leave unset.
func (s *Scheduler) SetOnClusterStart(fn func(resourceType string)) {
	s.onClusterStart = fn
	s.seenCluster = map[string]bool{}
}

func New(inv Invoker, classify Classifier, led *ledger.Ledger, bundle *output.Bundle, concurrency int) *Scheduler {
	if concurrency < 1 {
		concurrency = 8
	}
	return &Scheduler{
		inv: inv, classify: classify, led: led, bundle: bundle,
		concurrency: concurrency, sem: make(chan struct{}, concurrency),
	}
}

// SetDebug enables per-operation in/out/error logging to w (typically stderr).
func (s *Scheduler) SetDebug(w io.Writer) { s.debug = w }

// Progress is a lock-free live snapshot of the collection phase.
type Progress struct {
	SeedsDone int
	Detail    int
	Artifacts int
	OK        int
	Empty     int
	Denied    int
	Throttled int
	Errored   int
	Skipped   int
}

// Snapshot returns the current counters for a live progress renderer.
func (s *Scheduler) Snapshot() Progress {
	return Progress{
		SeedsDone: int(s.seedsDone.Load()),
		Detail:    int(s.detail.Load()),
		Artifacts: int(s.artifacts.Load()),
		OK:        int(s.okC.Load()),
		Empty:     int(s.emptyC.Load()),
		Denied:    int(s.deniedC.Load()),
		Throttled: int(s.throttleC.Load()),
		Errored:   int(s.errC.Load()),
		Skipped:   int(s.skippedC.Load()),
	}
}

// tally records a terminal outcome in the live counters and, for seeds (the
// enumerate calls, Step<0), advances the percentage denominator.
func (s *Scheduler) tally(t Task, status model.Outcome) {
	switch status {
	case model.OutcomeOK:
		s.okC.Add(1)
	case model.OutcomeEmpty:
		s.emptyC.Add(1)
	case model.OutcomeDenied:
		s.deniedC.Add(1)
	case model.OutcomeThrottled:
		s.throttleC.Add(1)
	case model.OutcomeError:
		s.errC.Add(1)
	case model.OutcomeSkipped:
		s.skippedC.Add(1)
	}
	if t.Step < 0 {
		s.seedsDone.Add(1)
	} else {
		s.detail.Add(1)
	}
}

// noteCluster invokes onClusterStart the first time a resource type is seen.
func (s *Scheduler) noteCluster(rt string) {
	if s.onClusterStart == nil {
		return
	}
	s.seenMu.Lock()
	first := !s.seenCluster[rt]
	if first {
		s.seenCluster[rt] = true
	}
	s.seenMu.Unlock()
	if first {
		s.onClusterStart(rt)
	}
}

// logOp writes one in/out/error debug line for an operation.
func (s *Scheduler) logOp(t Task, callRegion string, n int, dur time.Duration, err error) {
	if s.debug == nil {
		return
	}
	loc := callRegion
	if loc == "" {
		loc = "-"
	}
	if err != nil {
		fmt.Fprintf(s.debug, "[debug] %s region=%s%s → ERROR %s (%s)\n",
			t.Op, loc, fmtParams(t.Params), s.classify(err)+": "+shortErr(err), fmtDur(dur))
		return
	}
	fmt.Fprintf(s.debug, "[debug] %s region=%s%s → %d recs (%s)\n",
		t.Op, loc, fmtParams(t.Params), n, fmtDur(dur))
}

// Run executes all seed tasks (and their dynamically-spawned children) to
// completion. Returns the number of artifacts emitted.
func (s *Scheduler) Run(ctx context.Context, seeds []Task) int {
	for _, t := range seeds {
		s.wg.Add(1)
		go s.run(ctx, t)
	}
	s.wg.Wait()
	return int(s.artifacts.Load())
}

func (s *Scheduler) run(ctx context.Context, t Task) {
	defer s.wg.Done()
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	s.led.Plan(t.ID, t.Scope, t.Res.ResourceType, t.Op)
	s.led.Start(t.ID)
	if t.Step < 0 {
		s.noteCluster(t.Res.ResourceType)
	}

	callRegion := t.CallRegion
	if callRegion == "" {
		callRegion = t.Scope.Region
	}
	t0 := time.Now()
	recs, err := s.inv.Invoke(ctx, t.Op, callRegion, t.Params)
	s.logOp(t, callRegion, len(recs), time.Since(t0), err)
	if err != nil {
		var status model.Outcome
		switch s.classify(err) {
		case "denied":
			status = model.OutcomeDenied
		case "throttled":
			status = model.OutcomeThrottled
		default:
			status = model.OutcomeError
		}
		s.led.Finish(t.ID, status, 0, shortErr(err))
		s.tally(t, status)
		return
	}
	if len(recs) == 0 {
		s.led.Finish(t.ID, model.OutcomeEmpty, 0, "")
		s.tally(t, model.OutcomeEmpty)
		return
	}
	s.led.Finish(t.ID, model.OutcomeOK, len(recs), "")
	s.tally(t, model.OutcomeOK)

	lastStep := len(t.Res.Detail) - 1
	for _, rec := range recs {
		merged := mergeRecords(t.Record, rec)
		if t.Step >= lastStep {
			// End of the chain — emit the artifact.
			s.emit(t, merged)
			continue
		}
		// Spawn the next detail step, resolving its bindings from `merged`.
		next := t.Step + 1
		det := t.Res.Detail[next]
		params, ok := resolveBindings(det.Bind, merged)
		childID := fmt.Sprintf("%s/%s/%s", t.Scope.Region, t.Res.ResourceType, det.Operation)
		if id := idOf(merged); id != "" {
			childID += "/" + id
		}
		if !ok {
			// A binding couldn't resolve — record it, don't crash.
			s.led.Plan(childID, t.Scope, t.Res.ResourceType, det.Operation)
			s.led.Finish(childID, model.OutcomeSkipped, 0, "unresolved_binding")
			s.skippedC.Add(1)
			s.detail.Add(1)
			continue
		}
		child := Task{
			ID: childID, Scope: t.Scope, CallRegion: t.CallRegion, Res: t.Res, Op: det.Operation,
			Step: next, Params: params, Record: merged,
		}
		s.wg.Add(1)
		go s.run(ctx, child)
	}
}

// emit builds and writes the normalized Artifact for a completed chain.
func (s *Scheduler) emit(t Task, rec map[string]any) {
	e := t.Res.Enumerate
	art := model.Artifact{
		Provider: t.Scope.Provider,
		// providers may override the owning account per-record (e.g. Azure multi-sub:
		// one ARG query returns resources spanning subscriptions).
		Account:      firstNonEmptyStr(str(rec["__account"]), t.Scope.Account),
		Scope:        t.Scope,
		ResourceType: t.Res.ResourceType,
		NodeType:     t.Res.NodeType,
		NativeID:     str(rec[e.IDField]),
		ARN:          str(rec[e.ARNField]),
		Attributes:   map[string]any{},
		CollectedBy:  []string{e.Operation},
		CapturedAt:   time.Now().UTC(),
	}
	for _, a := range e.Attributes {
		if v, ok := rec[a]; ok {
			art.Attributes[a] = v
		}
	}
	for _, det := range t.Res.Detail {
		art.CollectedBy = append(art.CollectedBy, det.Operation)
		for _, cap := range det.Capture {
			if v, ok := rec[cap]; ok {
				art.Attributes[cap] = v
			}
		}
	}
	if ref := str(rec["evidence_ref"]); ref != "" {
		art.EvidenceRef = ref
	}
	shard := "inventory/" + sanitize(t.Res.ResourceType) + ".ndjson"
	_ = s.bundle.AppendJSON(shard, art)
	s.artifacts.Add(1)
}

func resolveBindings(bind map[string]string, rec map[string]any) (map[string]string, bool) {
	params := map[string]string{}
	for param, ref := range bind {
		if strings.HasPrefix(ref, "$") {
			v, ok := rec[strings.TrimPrefix(ref, "$")]
			if !ok || str(v) == "" {
				return nil, false
			}
			params[param] = str(v)
		} else {
			params[param] = ref
		}
	}
	return params, true
}

func mergeRecords(base, add map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(add))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

func idOf(rec map[string]any) string {
	for _, k := range []string{"function_name", "project_name", "user_name", "bucket_name", "native_id"} {
		if v := str(rec[k]); v != "" {
			return v
		}
	}
	return ""
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sanitize(s string) string { return strings.ReplaceAll(s, ":", "-") }

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		return s[:160]
	}
	return s
}

// fmtParams renders an operation's params compactly for a debug line, e.g.
// " FunctionName=foo bucket=bar" (empty string when there are none). Keys are
// sorted so the output is stable across runs.
func fmtParams(p map[string]string) string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%s", k, p[k])
	}
	return b.String()
}

// fmtDur renders a duration compactly for debug lines.
func fmtDur(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(10 * time.Millisecond).String()
}
