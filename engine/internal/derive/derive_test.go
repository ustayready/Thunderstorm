package derive

import (
	"testing"
	"time"

	"thunderstorm/engine/internal/model"
)

func e(typ, src, tgt, state string, w float64) model.Edge {
	return model.Edge{
		EdgeID: model.EdgeID(typ, src, tgt, ""), Type: typ, Source: src, Target: tgt,
		State: state, Confidence: 1.0, Weight: w, Nature: model.NatureExplicit,
	}
}

func has(edges []model.Edge, typ, src, tgt string) *model.Edge {
	for i := range edges {
		if edges[i].Type == typ && edges[i].Source == src && edges[i].Target == tgt {
			return &edges[i]
		}
	}
	return nil
}

// CanAssume(p->role) + CanReadSecret(role->secret) => derived CanReadSecret(p->secret).
func TestInheritCapabilityViaAssume(t *testing.T) {
	edges := []model.Edge{
		e("CanAssume", "p", "role", model.StateActive, 1),
		e("CanReadSecret", "role", "secret", model.StateActive, 1),
	}
	d := Derive(edges, nil, time.Now())
	got := has(d, "CanReadSecret", "p", "secret")
	if got == nil {
		t.Fatalf("expected derived CanReadSecret p->secret; got %+v", d)
	}
	if got.Nature != model.NatureDerived || got.RuleID != "inherit-via-assume" {
		t.Errorf("nature/rule = %s/%s", got.Nature, got.RuleID)
	}
	if len(got.DerivedFrom) != 2 {
		t.Errorf("derived_from = %v want 2 contributors", got.DerivedFrom)
	}
}

// Multi-hop must collapse to a fixpoint: p->roleA->roleB->secret.
func TestFixpointTwoAssumes(t *testing.T) {
	edges := []model.Edge{
		e("CanAssume", "p", "roleA", model.StateActive, 1),
		e("CanAssume", "roleA", "roleB", model.StateActive, 1),
		e("CanReadSecret", "roleB", "secret", model.StateActive, 1),
	}
	d := Derive(edges, nil, time.Now())
	if has(d, "CanReadSecret", "p", "secret") == nil {
		t.Fatalf("expected p->secret via two assumes; got %+v", d)
	}
}

// State propagation: a CONDITIONAL contributor yields a CONDITIONAL derived edge.
func TestStatePropagationWeakest(t *testing.T) {
	edges := []model.Edge{
		e("CanAssume", "p", "role", model.StateConditional, 1),
		e("CanReadSecret", "role", "secret", model.StateActive, 1),
	}
	d := Derive(edges, nil, time.Now())
	got := has(d, "CanReadSecret", "p", "secret")
	if got == nil || got.State != model.StateConditional {
		t.Errorf("expected CONDITIONAL derived edge, got %+v", got)
	}
}

// ExecutesAs inheritance: compute -ExecutesAs-> role -CanReadData-> bucket.
func TestInheritViaExecutesAs(t *testing.T) {
	edges := []model.Edge{
		e("ExecutesAs", "fn", "role", model.StateActive, 1),
		e("CanReadData", "role", "bucket", model.StateActive, 2),
	}
	d := Derive(edges, nil, time.Now())
	if has(d, "CanReadData", "fn", "bucket") == nil {
		t.Errorf("expected fn->bucket via ExecutesAs; got %+v", d)
	}
}

// Non-capability second clauses must not propagate (e.g. MemberOf).
func TestNonCapabilityDoesNotPropagate(t *testing.T) {
	edges := []model.Edge{
		e("CanAssume", "p", "role", model.StateActive, 1),
		e("CrossAccountTrust", "role", "x", model.StateActive, 1),
	}
	d := Derive(edges, nil, time.Now())
	if has(d, "CrossAccountTrust", "p", "x") != nil {
		t.Errorf("CrossAccountTrust must not inherit through CanAssume")
	}
}

// Full compute-control chain: attacker CanModifyCode fn, fn ExecutesAs role,
// role CanReadSecret secret => attacker CanReadSecret secret (fixpoint), and
// attacker CanExecuteAs role.
func TestComputeControlInheritanceChain(t *testing.T) {
	edges := []model.Edge{
		e("CanModifyCode", "attacker", "fn", model.StateActive, 1),
		e("ExecutesAs", "fn", "role", model.StateActive, 1),
		e("CanReadSecret", "role", "secret", model.StateActive, 1),
	}
	d := Derive(edges, nil, time.Now())
	if has(d, "CanReadSecret", "attacker", "secret") == nil {
		t.Errorf("expected attacker -> secret via compute control; got %s", dumpTypes(d))
	}
	if has(d, "CanExecuteAs", "attacker", "role") == nil {
		t.Errorf("expected attacker CanExecuteAs role; got %s", dumpTypes(d))
	}
}

// Controlling a role's trust policy, where the target is a Role, is escalation.
func TestControlIdentityIsEscalation(t *testing.T) {
	edges := []model.Edge{e("CanModifyTrust", "p", "role", model.StateActive, 1)}
	nt := map[string]string{"role": "Role", "p": "HumanIdentity"}
	d := Derive(edges, nt, time.Now())
	esc := has(d, "CanEscalateTo", "p", "role")
	if esc == nil {
		t.Fatalf("expected CanEscalateTo p->role; got %s", dumpTypes(d))
	}
	if esc.RuleID != "control-identity-is-escalation" {
		t.Errorf("rule = %s", esc.RuleID)
	}
}

// The same control edge onto a NON-identity target must NOT be escalation.
func TestControlNonIdentityNotEscalation(t *testing.T) {
	edges := []model.Edge{e("CanModifyPolicy", "p", "bucket", model.StateActive, 1)}
	nt := map[string]string{"bucket": "ObjectStorage", "p": "HumanIdentity"}
	d := Derive(edges, nt, time.Now())
	if has(d, "CanEscalateTo", "p", "bucket") != nil {
		t.Errorf("CanEscalateTo must require an identity target")
	}
}

// Credential chain: read a secret that is CredentialsFor an identity => impersonate.
func TestCredentialChainImpersonate(t *testing.T) {
	edges := []model.Edge{
		e("CanReadSecret", "p", "secret", model.StateActive, 1),
		e("CredentialsFor", "secret", "svcacct", model.StateActive, 1),
	}
	nt := map[string]string{"svcacct": "ServiceIdentity"}
	d := Derive(edges, nt, time.Now())
	if has(d, "CanImpersonate", "p", "svcacct") == nil {
		t.Errorf("expected CanImpersonate p->svcacct; got %s", dumpTypes(d))
	}
	// and impersonation of an identity is escalation
	if has(d, "CanEscalateTo", "p", "svcacct") == nil {
		t.Errorf("expected CanEscalateTo via impersonation; got %s", dumpTypes(d))
	}
}

// Trigger a runner that executes as a role => CanExecuteAs (cicd/messaging).
func TestTriggerExecutesAs(t *testing.T) {
	edges := []model.Edge{
		e("CanTrigger", "p", "runner", model.StateActive, 1),
		e("ExecutesAs", "runner", "role", model.StateActive, 1),
	}
	if has(Derive(edges, nil, time.Now()), "CanExecuteAs", "p", "role") == nil {
		t.Errorf("expected CanExecuteAs p->role via trigger")
	}
}

// Same-source join: modify a compute's config AND pass it an identity => execute as it.
func TestConfigIdentitySwapSameSource(t *testing.T) {
	edges := []model.Edge{
		e("CanModifyConfiguration", "p", "fn", model.StateActive, 1),
		e("CanPassIdentity", "p", "role", model.StateActive, 1),
	}
	if has(Derive(edges, nil, time.Now()), "CanExecuteAs", "p", "role") == nil {
		t.Errorf("expected CanExecuteAs p->role via config identity swap")
	}
}

// Same-target join: poison an image a consumer references => modify the consumer.
func TestImagePoisonSameTarget(t *testing.T) {
	edges := []model.Edge{
		e("CanModifyCode", "p", "imagestore", model.StateActive, 1),
		e("ContainsResourceReference", "consumer", "imagestore", model.StateActive, 1),
	}
	got := has(Derive(edges, nil, time.Now()), "CanModifyCode", "p", "consumer")
	if got == nil {
		t.Fatalf("expected CanModifyCode p->consumer via image poisoning")
	}
	if got.Nature != model.NatureDerived {
		t.Errorf("nature = %s", got.Nature)
	}
}

// Federation: an external mapping to an identity confers CanFederateAs, which in
// turn yields CanEnterAccount and CanImpersonate, and is escalation.
func TestFederationChain(t *testing.T) {
	edges := []model.Edge{e("ExternalIdentityMapsTo", "gh", "role", model.StateActive, 1)}
	nt := map[string]string{"role": "Role", "gh": "FederatedIdentity"}
	d := Derive(edges, nt, time.Now())
	for _, typ := range []string{"CanFederateAs", "CanEnterAccount", "CanImpersonate", "CanEscalateTo"} {
		if has(d, typ, "gh", "role") == nil {
			t.Errorf("expected %s gh->role in federation chain; got %s", typ, dumpTypes(d))
		}
	}
}

// Network: an internet exposure or private link becomes CanNetworkReach, and two
// reach hops chain (LB proxy).
func TestNetworkReachPromotionsAndChain(t *testing.T) {
	edges := []model.Edge{
		e("ExposedToInternet", "lb", "anon", model.StateActive, 1),
		e("CanNetworkReach", "anon2", "lb2", model.StateActive, 1),
		e("CanNetworkReach", "lb2", "backend", model.StateActive, 1),
	}
	d := Derive(edges, nil, time.Now())
	if has(d, "CanNetworkReach", "lb", "anon") == nil {
		t.Errorf("expected ExposedToInternet -> CanNetworkReach")
	}
	if has(d, "CanNetworkReach", "anon2", "backend") == nil {
		t.Errorf("expected LB-proxy CanNetworkReach chain anon2->backend")
	}
}

// Hierarchy: controlling a parent that Contains a child => control the child.
func TestHierarchyControlContains(t *testing.T) {
	edges := []model.Edge{
		e("Controls", "p", "ou", model.StateActive, 1),
		e("Contains", "ou", "account", model.StateActive, 1),
	}
	if has(Derive(edges, nil, time.Now()), "Controls", "p", "account") == nil {
		t.Errorf("expected Controls p->account via Contains")
	}
}

func dumpTypes(edges []model.Edge) string {
	out := ""
	for _, e := range edges {
		out += e.Type + "(" + e.Source + "->" + e.Target + ") "
	}
	return out
}
