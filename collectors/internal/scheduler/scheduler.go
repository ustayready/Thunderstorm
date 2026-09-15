// Package scheduler executes the Collection DAG: it runs each resource's
// enumerate call, then fans out per-item detail calls with their bindings
// resolved from the enumerated record. Failures are
// bulkheaded — one task's error never aborts the run; it becomes a ledger row.
package scheduler

import (
	"context"
	"fmt"
	"strings"
	"sync"
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

	mu        sync.Mutex
	artifacts int
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

// Run executes all seed tasks (and their dynamically-spawned children) to
// completion. Returns the number of artifacts emitted.
func (s *Scheduler) Run(ctx context.Context, seeds []Task) int {
	for _, t := range seeds {
		s.wg.Add(1)
		go s.run(ctx, t)
	}
	s.wg.Wait()
	return s.artifacts
}

func (s *Scheduler) run(ctx context.Context, t Task) {
	defer s.wg.Done()
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	s.led.Plan(t.ID, t.Scope, t.Res.ResourceType, t.Op)
	s.led.Start(t.ID)

	callRegion := t.CallRegion
	if callRegion == "" {
		callRegion = t.Scope.Region
	}
	recs, err := s.inv.Invoke(ctx, t.Op, callRegion, t.Params)
	if err != nil {
		switch s.classify(err) {
		case "denied":
			s.led.Finish(t.ID, model.OutcomeDenied, 0, shortErr(err))
		case "throttled":
			s.led.Finish(t.ID, model.OutcomeThrottled, 0, shortErr(err))
		default:
			s.led.Finish(t.ID, model.OutcomeError, 0, shortErr(err))
		}
		return
	}
	if len(recs) == 0 {
		s.led.Finish(t.ID, model.OutcomeEmpty, 0, "")
		return
	}
	s.led.Finish(t.ID, model.OutcomeOK, len(recs), "")

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
	s.mu.Lock()
	s.artifacts++
	s.mu.Unlock()
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
