package gcp

import (
	"context"
	"strings"
	"sync"
	"time"

	"thunderstorm/collector/internal/ledger"
	"thunderstorm/collector/internal/model"
	"thunderstorm/collector/internal/output"
)

// The GCP FACTS tier collects IAM allow-policy BINDINGS (project-level + resource-
// level) and expands the roles they reference to permissions. The engine (M5e
// evaluator_gcp) turns these into capability EDGES: a member with a role that
// includes, say, secretmanager.versions.access on a secret => CanReadSecret.
//
// Fact kinds (consumed by the evaluator, not direct edges):
//   iam_binding      Source=member  Target=resource|"project:<id>"  attrs={role,condition,level}
//   role_permissions Source=role    attrs={permissions:[...]}
//   hierarchy        Source=project  Target=parent (org/folder) — ancestry for inheritance

type factSink struct {
	b       *output.Bundle
	project string
	mu      sync.Mutex
	n       int
}

func (s *factSink) emit(f model.Fact) {
	f.CapturedAt = time.Now().UTC()
	if f.Provider == "" {
		f.Provider = "gcp"
	}
	_ = s.b.AppendJSON("facts/"+f.Kind+".ndjson", f)
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
}

func (s *factSink) scope() model.Scope {
	return model.Scope{Provider: "gcp", Account: s.project, Global: true}
}

// factResource declares a resource type whose per-resource IAM policy we collect.
type factResource struct {
	resourceType string
	listOp       string
	iamOp        string
	scope        string // "global" | "regional"
}

// The high-value resource-level IAM surfaces. Project-level bindings (below) cover
// broad grants; these add resource-specific grants (esp. SA impersonation policies).
var factResources = []factResource{
	{"gcp:iam:service-account", "iam.projects.serviceAccounts.list", "iam.projects.serviceAccounts.getIamPolicy", "global"},
	{"gcp:secretmanager:secret", "secretmanager.projects.secrets.list", "secretmanager.projects.secrets.getIamPolicy", "global"},
	{"gcp:storage:bucket", "storage.buckets.list", "storage.buckets.getIamPolicy", "global"},
	{"gcp:pubsub:topic", "pubsub.projects.topics.list", "pubsub.projects.topics.getIamPolicy", "global"},
	{"gcp:run:service", "run.projects.locations.services.list", "run.projects.locations.services.getIamPolicy", "regional"},
	{"gcp:cloudfunctions:function", "cloudfunctions.projects.locations.functions.list", "cloudfunctions.projects.locations.functions.getIamPolicy", "global"},
	{"gcp:artifactregistry:repository", "artifactregistry.projects.locations.repositories.list", "artifactregistry.projects.locations.repositories.getIamPolicy", "regional"},
}

// CollectFacts collects GCP IAM bindings + role permissions. Bulkheaded: an error
// on one resource is a ledger row, never fatal. Returns total facts emitted.
func (c *Client) CollectFacts(ctx context.Context, project string, locations []string,
	led *ledger.Ledger, b *output.Bundle, concurrency int) int {
	s := &factSink{b: b, project: project}
	roles := &roleSet{seen: map[string]bool{}}

	// 1. PROJECT IAM policy — broad grants that apply to every resource in the project.
	runFact(led, "global", "gcp:iam:project-policy", "cloudresourcemanager.projects.getIamPolicy", project, func() (int, error) {
		bindings, err := c.Invoke(ctx, "cloudresourcemanager.projects.getIamPolicy", "", map[string]string{"resource": "projects/" + project})
		if err != nil {
			return 0, err
		}
		return s.emitBindings(bindings, "project:"+project, "project", roles), nil
	})

	// 2. RESOURCE-level IAM policies. Enumerate each type, then getIamPolicy per item.
	for _, fr := range factResources {
		fr := fr
		locs := []string{""} // global: one pass
		if fr.scope == "regional" {
			locs = locations
		}
		for _, loc := range locs {
			loc := loc
			runFact(led, scopeName(loc), "gcp:"+strings.SplitN(fr.resourceType, ":", 3)[1]+":iam-policy", fr.iamOp, project, func() (int, error) {
				items, err := c.Invoke(ctx, fr.listOp, loc, nil)
				if err != nil {
					return 0, err
				}
				total := 0
				for _, item := range items {
					name := itemID(item)
					if name == "" {
						continue
					}
					bindings, e := c.Invoke(ctx, fr.iamOp, loc, map[string]string{"resource": name, "bucket": name, "name": name})
					if e != nil {
						continue // per-resource denial/absence — not fatal
					}
					total += s.emitBindings(bindings, name, "resource", roles)
				}
				return total, nil
			})
		}
	}

	// 3. ROLE expansion — for every distinct role seen, fetch its permissions.
	runFact(led, "global", "gcp:iam:role-permissions", "iam.roles.get", project, func() (int, error) {
		total := 0
		for _, role := range roles.list() {
			recs, err := c.Invoke(ctx, "iam.roles.get", "", map[string]string{"name": role})
			if err != nil || len(recs) == 0 {
				continue
			}
			perms := stringList(recs[0]["includedPermissions"])
			if len(perms) == 0 {
				continue
			}
			s.emit(model.Fact{Kind: "role_permissions", EdgeHint: "RoleGrants", Scope: s.scope(),
				Source: role, Attributes: map[string]any{"permissions": perms}})
			total++
		}
		return total, nil
	})

	return s.n
}

// emitBindings turns a getIamPolicy bindings[] array into iam_binding facts (one
// per member) and records the roles for later permission expansion.
func (s *factSink) emitBindings(bindings []Record, target, level string, roles *roleSet) int {
	n := 0
	for _, bnd := range bindings {
		role, _ := bnd["role"].(string)
		if role == "" {
			continue
		}
		roles.add(role)
		cond := ""
		if cm, ok := bnd["condition"].(map[string]any); ok {
			cond, _ = cm["expression"].(string)
		}
		for _, m := range stringList(bnd["members"]) {
			s.emit(model.Fact{Kind: "iam_binding", EdgeHint: "HasBinding", Scope: s.scope(),
				Source: m, Target: target,
				Attributes: map[string]any{"role": role, "condition": cond, "level": level}})
			n++
		}
	}
	return n
}

type roleSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (r *roleSet) add(role string) { r.mu.Lock(); r.seen[role] = true; r.mu.Unlock() }
func (r *roleSet) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.seen))
	for k := range r.seen {
		out = append(out, k)
	}
	return out
}

// runFact records one fact task in the ledger (mirrors the AWS facts bulkhead).
func runFact(led *ledger.Ledger, loc, resourceType, op, project string, fn func() (int, error)) {
	scope := model.Scope{Provider: "gcp", Account: project, Global: loc == ""}
	if loc != "" {
		scope.Region = loc
	}
	id := loc + "/" + resourceType
	if loc == "" {
		id = "global/" + resourceType
	}
	led.Plan(id, scope, resourceType, op)
	led.Start(id)
	n, err := fn()
	if err != nil {
		switch Classify(err) {
		case "denied":
			led.Finish(id, model.OutcomeDenied, n, shortErr(err))
		case "throttled":
			led.Finish(id, model.OutcomeThrottled, n, shortErr(err))
		default:
			led.Finish(id, model.OutcomeError, n, shortErr(err))
		}
		return
	}
	if n == 0 {
		led.Finish(id, model.OutcomeEmpty, 0, "")
	} else {
		led.Finish(id, model.OutcomeOK, n, "")
	}
}

func scopeName(loc string) string {
	if loc == "" {
		return "global"
	}
	return loc
}

func stringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
