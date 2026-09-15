package evaluator_gcp

import (
	"testing"
	"time"

	"thunderstorm/engine/internal/derive"
	"thunderstorm/engine/internal/model"
)

// --- fixture helpers ---

func saNode(email string) model.Node {
	return model.Node{NodeID: "gcp|proj|gcp:iam:service-account|" + email, NodeType: "ServiceAccount",
		Provider: "gcp", Account: "proj", ARN: "projects/proj/serviceAccounts/" + email}
}
func secretNode(name string) model.Node {
	full := "projects/proj/secrets/" + name
	return model.Node{NodeID: "gcp|proj|gcp:secretmanager:secret|" + full, NodeType: "Secret",
		Provider: "gcp", Account: "proj", ARN: full}
}
func bucketNode(name string) model.Node {
	return model.Node{NodeID: "gcp|proj|gcp:storage:bucket|" + name, NodeType: "ObjectStorage",
		Provider: "gcp", Account: "proj", ARN: name}
}
func projectNode() model.Node {
	return model.Node{NodeID: "gcp|proj|gcp:resourcemanager:project|projects/proj", NodeType: "Project",
		Provider: "gcp", Account: "proj", ARN: "projects/proj"}
}
func rolePerms(role string, perms ...string) model.Fact {
	ps := make([]any, len(perms))
	for i, p := range perms {
		ps[i] = p
	}
	return model.Fact{Kind: "role_permissions", Source: role, Attributes: map[string]any{"permissions": ps}}
}
func binding(member, target, role, level, cond string) model.Fact {
	// Scope.Account mirrors the real collector (providers/gcp/facts.go): every iam_binding
	// fact carries its project, which the evaluator uses to scope project-wide grants.
	return model.Fact{Kind: "iam_binding", Source: member, Target: target,
		Scope:      model.Scope{Provider: "gcp", Account: "proj", Global: true},
		Attributes: map[string]any{"role": role, "level": level, "condition": cond}}
}

// edgeExists reports whether an edge of type t from source-native to target-native exists.
func edgeExists(edges []model.Edge, t, srcNative, tgtNative string) bool {
	for _, e := range edges {
		if e.Type == t && lastSegOf(e.Source) == srcNative && lastSegOf(e.Target) == tgtNative {
			return true
		}
	}
	return false
}
func lastSegOf(nodeID string) string {
	parts := splitPipe(nodeID)
	return parts[len(parts)-1]
}
func splitPipe(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '|' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	return append(out, cur)
}

func runFull(nodes []model.Node, facts []model.Fact) ([]model.Edge, map[string]string) {
	at := time.Unix(0, 0)
	edges, extra := EvaluatePermissions(facts, nodes, at)
	all := append(append([]model.Node{}, nodes...), extra...)
	nodeType := map[string]string{}
	for _, n := range all {
		nodeType[n.NodeID] = n.NodeType
	}
	edges = append(edges, derive.Derive(edges, nodeType, at)...)
	return edges, nodeType
}

// GOLDEN: an SA that can impersonate another SA inherits everything that SA can do,
// and the impersonation promotes to an escalation edge. This is the GCP privesc
// backbone (getAccessToken) — the analog of AWS assume-role chaining.
func TestGCP_ImpersonationChainInheritsAndEscalates(t *testing.T) {
	nodes := []model.Node{saNode("attacker@p"), saNode("target@p"), secretNode("crown")}
	facts := []model.Fact{
		rolePerms("roles/iam.serviceAccountTokenCreator", "iam.serviceAccounts.getAccessToken"),
		rolePerms("roles/secretmanager.secretAccessor", "secretmanager.versions.access"),
		// attacker can impersonate target (resource-level binding on the target SA)
		binding("serviceAccount:attacker@p", "projects/proj/serviceAccounts/target@p", "roles/iam.serviceAccountTokenCreator", "resource", ""),
		// target can read the crown secret
		binding("serviceAccount:target@p", "projects/proj/secrets/crown", "roles/secretmanager.secretAccessor", "resource", ""),
	}
	edges, _ := runFull(nodes, facts)

	if !edgeExists(edges, "CanImpersonate", "attacker@p", "target@p") {
		t.Error("attacker should CanImpersonate target")
	}
	if !edgeExists(edges, "CanReadSecret", "target@p", "projects/proj/secrets/crown") {
		t.Error("target should CanReadSecret crown")
	}
	// derived: attacker inherits target's secret read via impersonation
	if !edgeExists(edges, "CanReadSecret", "attacker@p", "projects/proj/secrets/crown") {
		t.Error("attacker should inherit CanReadSecret crown via impersonation (derived)")
	}
	// derived: impersonating an SA is an escalation
	if !edgeExists(edges, "CanEscalateTo", "attacker@p", "target@p") {
		t.Error("attacker should CanEscalateTo target (derived)")
	}
}

// GOLDEN: a project-level grant inherits to EVERY resource of the class (GCP's
// automatic downward inheritance) — a project editor can read all buckets.
func TestGCP_ProjectLevelBindingInheritsToAllResources(t *testing.T) {
	nodes := []model.Node{saNode("editor@p"), bucketNode("bucket-a"), bucketNode("bucket-b")}
	facts := []model.Fact{
		rolePerms("roles/editor", "storage.objects.get"),
		binding("serviceAccount:editor@p", "project:proj", "roles/editor", "project", ""),
	}
	edges, _ := runFull(nodes, facts)
	if !edgeExists(edges, "CanReadData", "editor@p", "bucket-a") ||
		!edgeExists(edges, "CanReadData", "editor@p", "bucket-b") {
		t.Error("project-level editor should CanReadData ALL buckets")
	}
}

// GOLDEN: a CEL-conditioned binding produces a CONDITIONAL edge, not ACTIVE.
func TestGCP_ConditionalBindingIsConditional(t *testing.T) {
	nodes := []model.Node{saNode("user@p"), secretNode("s1")}
	facts := []model.Fact{
		rolePerms("roles/secretmanager.secretAccessor", "secretmanager.versions.access"),
		binding("serviceAccount:user@p", "projects/proj/secrets/s1", "roles/secretmanager.secretAccessor", "resource",
			"request.time < timestamp('2030-01-01T00:00:00Z')"),
	}
	edges, _ := EvaluatePermissions(facts, nodes, time.Unix(0, 0))
	found := false
	for _, e := range edges {
		if e.Type == "CanReadSecret" {
			found = true
			if e.State != model.StateConditional {
				t.Errorf("conditioned binding must yield CONDITIONAL edge, got %s", e.State)
			}
		}
	}
	if !found {
		t.Error("expected a CanReadSecret edge")
	}
}

// GOLDEN: setIamPolicy on the project => CanGrantPermission, which the derivation
// promotes to CanControl (self-grant owner is total control).
func TestGCP_SetIamPolicyIsControl(t *testing.T) {
	nodes := []model.Node{saNode("owner@p"), projectNode()}
	facts := []model.Fact{
		rolePerms("roles/owner", "resourcemanager.projects.setIamPolicy"),
		binding("serviceAccount:owner@p", "project:proj", "roles/owner", "project", ""),
	}
	edges, _ := runFull(nodes, facts)
	if !edgeExists(edges, "CanGrantPermission", "owner@p", "projects/proj") {
		t.Error("owner should CanGrantPermission on the project")
	}
	if !edgeExists(edges, "CanControl", "owner@p", "projects/proj") {
		t.Error("CanGrantPermission should promote to CanControl (derived)")
	}
}

// GOLDEN: setIamPolicy on a resource (not just the project) is self-grant and must
// promote to CanControl — e.g. rewriting a bucket's IAM policy owns the bucket.
func TestGCP_ResourceSetIamPolicyIsControl(t *testing.T) {
	nodes := []model.Node{saNode("user@p"), bucketNode("bucket-a")}
	facts := []model.Fact{
		rolePerms("roles/storage.admin", "storage.buckets.setIamPolicy"),
		binding("serviceAccount:user@p", "bucket-a", "roles/storage.admin", "resource", ""),
	}
	edges, _ := runFull(nodes, facts)
	if !edgeExists(edges, "CanModifyPolicy", "user@p", "bucket-a") {
		t.Error("user should CanModifyPolicy the bucket")
	}
	if !edgeExists(edges, "CanControl", "user@p", "bucket-a") {
		t.Error("bucket setIamPolicy should promote to CanControl (derived)")
	}
}

// GOLDEN: when a member has BOTH a conditional and an unconditional grant that
// produce the same edge, the ACTIVE (unconditional) grant must win — a CONDITIONAL
// emitted first must not mask the real access.
func TestGCP_UnconditionalGrantWinsOverConditional(t *testing.T) {
	nodes := []model.Node{saNode("user@p"), secretNode("s1")}
	facts := []model.Fact{
		rolePerms("roles/secretmanager.secretAccessor", "secretmanager.versions.access"),
		// project-wide CONDITIONAL grant (emitted first, project loop runs before resource loop)
		binding("serviceAccount:user@p", "project:proj", "roles/secretmanager.secretAccessor", "project",
			"request.time < timestamp('2030-01-01T00:00:00Z')"),
		// resource-scoped UNCONDITIONAL grant on the same secret
		binding("serviceAccount:user@p", "projects/proj/secrets/s1", "roles/secretmanager.secretAccessor", "resource", ""),
	}
	edges, _ := EvaluatePermissions(facts, nodes, time.Unix(0, 0))
	var found bool
	for _, e := range edges {
		if e.Type == "CanReadSecret" && lastSegOf(e.Target) == "projects/proj/secrets/s1" {
			found = true
			if e.State != model.StateActive {
				t.Errorf("unconditional grant must win => ACTIVE, got %s", e.State)
			}
		}
	}
	if !found {
		t.Error("expected a CanReadSecret edge to s1")
	}
}

// GOLDEN: project takeover — an SA with projectIamAdmin (resourcemanager.projects.setIamPolicy)
// can self-grant Owner and thus read EVERY resource in the project, including a crown secret
// that no lesser identity can access. This is the top rung of the GCP escalation ladder.
func TestGCP_ProjectTakeoverReachesAllResources(t *testing.T) {
	nodes := []model.Node{saNode("iamadmin@p"), projectNode(), secretNode("crown"), bucketNode("bkt")}
	facts := []model.Fact{
		rolePerms("roles/resourcemanager.projectIamAdmin", "resourcemanager.projects.setIamPolicy"),
		binding("serviceAccount:iamadmin@p", "project:proj", "roles/resourcemanager.projectIamAdmin", "project", ""),
	}
	edges, _ := runFull(nodes, facts)
	if !edgeExists(edges, "CanGrantPermission", "iamadmin@p", "projects/proj") {
		t.Error("iamadmin should CanGrantPermission on the project")
	}
	// takeover: owns the project -> reads the crown secret and controls the bucket
	if !edgeExists(edges, "CanReadSecret", "iamadmin@p", "projects/proj/secrets/crown") {
		t.Error("project takeover should yield CanReadSecret on the crown secret (derived)")
	}
	if !edgeExists(edges, "CanControl", "iamadmin@p", "bkt") {
		t.Error("project takeover should yield CanControl over every resource (derived)")
	}
}

// GOLDEN: Google-managed service agents (robots) are NOT modeled as attack sources —
// their roles include broad perms Google exercises internally, but an attacker can't
// obtain their credentials. A robot with project-wide getAccessToken must NOT produce
// impersonation edges.
func TestGCP_GoogleManagedAgentsAreNotSources(t *testing.T) {
	nodes := []model.Node{saNode("target@p")}
	facts := []model.Fact{
		rolePerms("roles/cloudbuild.serviceAgent", "iam.serviceAccounts.getAccessToken"),
		binding("serviceAccount:service-123@gcp-sa-cloudbuild.iam.gserviceaccount.com",
			"project:proj", "roles/cloudbuild.serviceAgent", "project", ""),
	}
	edges, _ := EvaluatePermissions(facts, nodes, time.Unix(0, 0))
	for _, e := range edges {
		if lastSegOf(e.Source) == "service-123@gcp-sa-cloudbuild.iam.gserviceaccount.com" {
			t.Errorf("google-managed agent must not be a capability source; got %s", e.Type)
		}
	}
}

// GOLDEN: a user member not in inventory is synthesized as a HumanIdentity node,
// and allUsers becomes an Everyone node (public grant).
func TestGCP_SynthesizesExternalMembers(t *testing.T) {
	nodes := []model.Node{secretNode("s1")}
	facts := []model.Fact{
		rolePerms("roles/secretmanager.secretAccessor", "secretmanager.versions.access"),
		binding("user:alice@example.com", "projects/proj/secrets/s1", "roles/secretmanager.secretAccessor", "resource", ""),
		binding("allUsers", "projects/proj/secrets/s1", "roles/secretmanager.secretAccessor", "resource", ""),
	}
	_, extra := EvaluatePermissions(facts, nodes, time.Unix(0, 0))
	var human, everyone bool
	for _, n := range extra {
		if n.NodeType == "HumanIdentity" {
			human = true
		}
		if n.NodeType == "Everyone" {
			everyone = true
		}
	}
	if !human {
		t.Error("user:alice should synthesize a HumanIdentity node")
	}
	if !everyone {
		t.Error("allUsers should synthesize an Everyone node")
	}
}
