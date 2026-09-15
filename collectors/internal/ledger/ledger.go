// Package ledger tracks every planned collection unit through its lifecycle so
// coverage gaps are impossible to hide. It is the spine
// of the "never silently miss a region/datapoint" guarantee.
package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"thunderstorm/collector/internal/model"
)

// ReportOpts carries preflight data for the reconciliation report.
type ReportOpts struct {
	RequiredPermissions []string // what the run needs (from the registry)
	DeniedPermissions   []string // subset actually denied at runtime
}

// Ledger is safe for concurrent use by the scheduler's workers.
type Ledger struct {
	mu   sync.Mutex
	rows map[string]*model.LedgerRow
}

func New() *Ledger { return &Ledger{rows: map[string]*model.LedgerRow{}} }

// LoadCoverage reads a prior run's ledger/coverage.ndjson (for --resume).
func LoadCoverage(path string) ([]model.LedgerRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []model.LedgerRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var r model.LedgerRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, sc.Err()
}

// prior holds a resumed run's terminal-success task ids so they can be skipped.
type Prior struct{ done map[string]bool }

// NewPrior indexes a prior coverage set: a task is "done" (skippable) if it
// reached a terminal SUCCESS-ish state (ok/empty/denied/skipped). error/throttled/
// running/planned are NOT done — they re-run.
func NewPrior(rows []model.LedgerRow) *Prior {
	p := &Prior{done: map[string]bool{}}
	for _, r := range rows {
		switch r.Status {
		case model.OutcomeOK, model.OutcomeEmpty, model.OutcomeDenied, model.OutcomeSkipped:
			p.done[r.TaskID] = true
		}
	}
	return p
}

// Done reports whether a task id already completed successfully in the prior run.
func (p *Prior) Done(id string) bool {
	if p == nil {
		return false
	}
	return p.done[id]
}

// Resumed records a task as skipped-because-already-done (for the new ledger).
func (l *Ledger) Resumed(taskID string, scope model.Scope, resourceType, operation string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows[taskID] = &model.LedgerRow{
		TaskID: taskID, Scope: scope, ResourceType: resourceType, Operation: operation,
		Status: model.OutcomeSkipped, Reason: "resumed_prior_run", EndedAt: time.Now().UTC(),
	}
}

// Plan registers a unit as planned BEFORE it runs. Idempotent per task id.
func (l *Ledger) Plan(taskID string, scope model.Scope, resourceType, operation string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.rows[taskID]; ok {
		return
	}
	l.rows[taskID] = &model.LedgerRow{
		TaskID: taskID, Scope: scope, ResourceType: resourceType,
		Operation: operation, Status: model.OutcomePlanned,
	}
}

func (l *Ledger) Start(taskID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.rows[taskID]; r != nil {
		r.Status = model.OutcomeRunning
		r.StartedAt = time.Now().UTC()
	}
}

// Finish records a terminal outcome. count = items produced; reason = why (for
// denied/skipped/error).
func (l *Ledger) Finish(taskID string, status model.Outcome, count int, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.rows[taskID]; r != nil {
		r.Status = status
		r.Count = count
		r.Reason = reason
		r.EndedAt = time.Now().UTC()
	}
}

// Rows returns a stable-sorted snapshot for serialization.
func (l *Ledger) Rows() []model.LedgerRow {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]model.LedgerRow, 0, len(l.rows))
	for _, r := range l.rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID < out[j].TaskID })
	return out
}

// Summary counts rows by outcome.
func (l *Ledger) Summary() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := map[string]int{}
	for _, r := range l.rows {
		m[string(r.Status)]++
	}
	return m
}

// IntegrityOK is true iff no row was left running/planned (a crash marker).
func (l *Ledger) IntegrityOK() bool {
	for _, r := range l.Rows() {
		if r.Status == model.OutcomeRunning || r.Status == model.OutcomePlanned {
			return false
		}
	}
	return true
}

// Report renders the human reconciliation report (report.md). This is the
// artifact that makes coverage explicit: a reader can see exactly what the graph
// will and won't contain, and why.
func (l *Ledger) Report(provider, account string, scopes []model.Scope, opts ReportOpts) string {
	rows := l.Rows()
	sum := l.Summary()
	var b strings.Builder
	fmt.Fprintf(&b, "# Collection reconciliation report\n\n")
	fmt.Fprintf(&b, "- provider: **%s**  account: **%s**\n", provider, account)
	fmt.Fprintf(&b, "- scopes discovered: **%d**\n", len(scopes))
	fmt.Fprintf(&b, "- tasks planned: **%d**\n\n", len(rows))

	fmt.Fprintf(&b, "## Outcomes\n\n| outcome | count |\n|---|---|\n")
	for _, k := range []model.Outcome{model.OutcomeOK, model.OutcomeEmpty, model.OutcomeDenied,
		model.OutcomeThrottled, model.OutcomeError, model.OutcomeSkipped,
		model.OutcomeRunning, model.OutcomePlanned} {
		if c := sum[string(k)]; c > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", k, c)
		}
	}

	// Preflight: what the run needed, and what was actually denied.
	if len(opts.RequiredPermissions) > 0 {
		fmt.Fprintf(&b, "\n## Preflight permissions\n\nThe run needs **%d** permissions",
			len(opts.RequiredPermissions))
		if len(opts.DeniedPermissions) == 0 {
			fmt.Fprintf(&b, "; **none were denied** — coverage is not permission-limited.\n")
		} else {
			fmt.Fprintf(&b, "; **%d were denied** (these shaped the coverage gaps below):\n\n",
				len(opts.DeniedPermissions))
			for _, p := range opts.DeniedPermissions {
				fmt.Fprintf(&b, "- `%s`\n", p)
			}
		}
	}

	// Classify rows once: inventory vs exposure vs meta; tally the rest.
	var denied, errored []model.LedgerRow
	skipReasons := map[string]int{}
	collected := map[string]int{} // service -> resources collected
	invEmpty := 0
	expHits, expProbedEmpty, expNoProbe, expSurfaces, expNoInv := 0, 0, 0, 0, 0
	metaOp := map[string]bool{"ec2:DescribeRegions": true, "sts:GetCallerIdentity": true, "region-scope": true}
	for _, r := range rows {
		switch r.Status {
		case model.OutcomeDenied:
			denied = append(denied, r)
		case model.OutcomeError, model.OutcomeThrottled:
			errored = append(errored, r)
		case model.OutcomeSkipped:
			reason := r.Reason
			if strings.HasPrefix(reason, "surface:") {
				reason = "surface (not invoked)"
			}
			skipReasons[reason]++
		}
		switch {
		case strings.HasPrefix(r.ResourceType, "exposure:"):
			switch {
			case r.Status == model.OutcomeOK:
				expHits += r.Count
			case r.Status == model.OutcomeEmpty:
				expProbedEmpty++
			case r.Reason == "no_probe_impl":
				expNoProbe++
			case strings.HasPrefix(r.Reason, "surface:"):
				expSurfaces++
			case r.Reason == "no_inventory_targets":
				expNoInv++
			}
		case strings.HasPrefix(r.ResourceType, "aws:") && r.ResourceType != "aws:region:scope" && !metaOp[r.Operation]:
			parts := strings.Split(r.ResourceType, ":")
			if r.Status == model.OutcomeOK && len(parts) >= 2 {
				collected[parts[1]] += r.Count
			} else if r.Status == model.OutcomeEmpty {
				invEmpty++
			}
		}
	}

	// Exposure prober summary (compact — per-site detail is in coverage.ndjson).
	fmt.Fprintf(&b, "\n## Exposure prober\n\n")
	fmt.Fprintf(&b, "- credential hits: **%d**\n", expHits)
	fmt.Fprintf(&b, "- read_api sites probed, no secret found: %d\n", expProbedEmpty)
	fmt.Fprintf(&b, "- surfaces recorded (write/create/data-plane — never invoked): %d\n", expSurfaces)
	fmt.Fprintf(&b, "- read_api sites with no probe implemented yet: %d\n", expNoProbe)
	if expNoInv > 0 {
		fmt.Fprintf(&b, "- read_api sites with no inventory targets: %d\n", expNoInv)
	}

	// Actionable failures — full detail (these shaped coverage).
	section := func(title string, rs []model.LedgerRow) {
		if len(rs) == 0 {
			return
		}
		sort.Slice(rs, func(i, j int) bool { return rs[i].Operation < rs[j].Operation })
		fmt.Fprintf(&b, "\n## %s (%d)\n\n", title, len(rs))
		for _, r := range rs {
			loc := r.Scope.Region
			if r.Scope.Global {
				loc = "global"
			}
			if loc == "" {
				loc = "-"
			}
			fmt.Fprintf(&b, "- `%s` @ %s — %s\n", r.Operation, loc, r.Reason)
		}
	}
	section("Permission-denied (expected coverage gaps)", denied)
	section("Errored / throttled (retryable — re-run resumes these)", errored)

	// Skipped — summarized by reason (full rows in coverage.ndjson).
	if len(skipReasons) > 0 {
		keys := make([]string, 0, len(skipReasons))
		for k := range skipReasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "\n## Skipped (by reason)\n\n| reason | count |\n|---|---|\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "| %s | %d |\n", k, skipReasons[k])
		}
	}

	// Collected resources by service, A–Z — what was actually gathered.
	svcNames := make([]string, 0, len(collected))
	total := 0
	for s, n := range collected {
		svcNames = append(svcNames, s)
		total += n
	}
	sort.Strings(svcNames)
	fmt.Fprintf(&b, "\n## Collected resources by service (A–Z)\n\n")
	fmt.Fprintf(&b, "**%d** resources across **%d** service(s); %d more service(s) enumerated but empty.\n\n",
		total, len(svcNames), invEmpty)
	fmt.Fprintf(&b, "| service | resources |\n|---|---|\n")
	for _, s := range svcNames {
		fmt.Fprintf(&b, "| %s | %d |\n", s, collected[s])
	}

	if !l.IntegrityOK() {
		fmt.Fprintf(&b, "\n## INTEGRITY WARNING\n\nSome tasks were left running/planned (crash?). Re-run to complete.\n")
	} else {
		fmt.Fprintf(&b, "\n_Integrity OK — every planned task reached a terminal outcome._\n")
	}
	return b.String()
}
