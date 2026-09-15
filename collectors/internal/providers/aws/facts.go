package aws

import (
	"context"
	"net/url"
	"sync"
	"time"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
)

// The FACTS tier gathers policy/trust/network facts that the engine turns into
// graph EDGES. Each Fact carries an edge_hint so the
// engine knows which edge it feeds. Facts are written to facts/<kind>.ndjson.

type factSink struct {
	b       *output.Bundle
	account string

	mu sync.Mutex
	n  int
}

// emit is safe for concurrent use — the underlying Bundle serializes writes; the
// mutex guards the running count for any collector that emits from goroutines.
func (s *factSink) emit(f model.Fact) {
	f.CapturedAt = time.Now().UTC()
	if f.Provider == "" {
		f.Provider = "aws"
	}
	_ = s.b.AppendJSON("facts/"+f.Kind+".ndjson", f)
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}

// CollectFacts runs every fact collector (IAM + S3 policies global; network +
// KMS policies per region). Bulkheaded: a collector error is a ledger row, never
// fatal. Returns total facts emitted.
func CollectFacts(ctx context.Context, c *Client, account string, regions []string, globalRegion string,
	led *ledger.Ledger, b *output.Bundle, concurrency int) int {
	// Build the task list, split into GLOBAL and REGIONAL. Each task gets its OWN
	// sink (sharing the concurrency-safe Bundle) so a collector's "s.n - start"
	// count is correct regardless of parallelism.
	type factTask struct {
		region, resourceType, op string
		fn                       func(s *factSink) (int, error)
	}
	var global, regional []factTask

	global = append(global,
		factTask{"global", "aws:iam:facts", "iam:facts",
			func(s *factSink) (int, error) { return collectIAMFacts(ctx, c, globalRegion, s) }},
		factTask{"global", "aws:s3:resource-policy", "s3:GetBucketPolicy",
			func(s *factSink) (int, error) { return collectS3PolicyFacts(ctx, c, globalRegion, s) }},
	)
	for _, r := range regions {
		r := r
		regional = append(regional,
			factTask{r, "aws:network:facts", "ec2:DescribeSecurityGroups",
				func(s *factSink) (int, error) { return collectNetworkFacts(ctx, c, r, s) }},
			factTask{r, "aws:kms:resource-policy", "kms:GetKeyPolicy",
				func(s *factSink) (int, error) { return collectKMSPolicyFacts(ctx, c, r, s) }},
		)
	}
	// Registered fact collectors (per-service resource policies etc., added via
	// facts_<svc>.go init()→registerFactCollector). Global once; regional per region.
	for _, rc := range factCollectors {
		rc := rc
		if rc.scope == "global" {
			global = append(global, factTask{"global", "aws:" + rc.name, rc.name,
				func(s *factSink) (int, error) { return rc.fn(ctx, c, globalRegion, s) }})
			continue
		}
		for _, r := range regions {
			r := r
			regional = append(regional, factTask{r, "aws:" + rc.name, rc.name,
				func(s *factSink) (int, error) { return rc.fn(ctx, c, r, s) }})
		}
	}

	if concurrency < 1 {
		concurrency = 12
	}
	var total int
	run := func(t factTask) int {
		s := &factSink{b: b, account: account}
		return runFactTask(led, t.region, t.resourceType, t.op, account, func() (int, error) { return t.fn(s) })
	}

	// GLOBAL collectors run SEQUENTIALLY. They mostly hit account-wide services
	// (IAM above all) that share one throttle bucket, so running them concurrently
	// only throttles each other — which silently dropped managed-policy documents
	// and made admins look powerless. Sequential here costs a few seconds; the real
	// win is the regional fan-out below.
	for _, t := range global {
		total += run(t)
	}

	// REGIONAL collectors run through the bounded pool — this is the ~17× win.
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var totalMu sync.Mutex
	for _, t := range regional {
		t := t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			n := run(t)
			totalMu.Lock()
			total += n
			totalMu.Unlock()
		}()
	}
	wg.Wait()
	return total
}

// factCollectorFn collects facts for one concern in one region (region is the
// global bootstrap region for global collectors). It appends to s and returns
// the count it added.
type factCollectorFn func(ctx context.Context, c *Client, region string, s *factSink) (int, error)

type factCollectorReg struct {
	name  string
	scope string // "global" | "regional"
	fn    factCollectorFn
}

var factCollectors []factCollectorReg

// registerFactCollector is called from facts_<svc>.go init() so fact breadth is
// added without editing this file (parallel-authoring safe).
func registerFactCollector(name, scope string, fn factCollectorFn) {
	factCollectors = append(factCollectors, factCollectorReg{name, scope, fn})
}

// runFactTask records the task in the ledger and returns the number of facts it
// emitted (0 on error, so partial failures don't inflate the total).
func runFactTask(led *ledger.Ledger, region, resourceType, op, account string, fn func() (int, error)) int {
	scope := model.Scope{Provider: "aws", Account: account, Region: region}
	if region == "global" || region == "" {
		scope = model.Scope{Provider: "aws", Account: account, Global: true}
	}
	id := region + "/" + resourceType
	led.Plan(id, scope, resourceType, op)
	led.Start(id)
	n, err := fn()
	if err != nil {
		switch Classify(err) {
		case "denied":
			led.Finish(id, model.OutcomeDenied, n, shortErrF(err))
		case "throttled":
			led.Finish(id, model.OutcomeThrottled, n, shortErrF(err))
		default:
			led.Finish(id, model.OutcomeError, n, shortErrF(err))
		}
		return n
	}
	if n == 0 {
		led.Finish(id, model.OutcomeEmpty, 0, "")
	} else {
		led.Finish(id, model.OutcomeOK, n, "")
	}
	return n
}

func (s *factSink) emitFact(kind, hint string, scope model.Scope, src, tgt string, attrs map[string]any) {
	s.emit(model.Fact{Kind: kind, EdgeHint: hint, Scope: scope, Source: src, Target: tgt, Attributes: attrs})
}

func (s *factSink) scopeGlobal() model.Scope {
	return model.Scope{Provider: "aws", Account: s.account, Global: true}
}
func (s *factSink) scopeRegion(r string) model.Scope {
	return model.Scope{Provider: "aws", Account: s.account, Region: r}
}

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func int32ptr(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func shortErrF(err error) string {
	s := err.Error()
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
