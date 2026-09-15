package evaluator

import (
	"sort"
	"strings"

	"thunderstorm/engine/internal/policy"
)

// Decision is the outcome of an effective-permission check.
type Decision struct {
	Allowed     bool     // is the principal effectively allowed?
	Conditional bool     // the allow (or a relevant deny) hinges on unresolved conditions
	Conditions  []string // human-readable unresolved condition operators/keys
	Via         string   // "identity" | "resource" | "identity+resource"
	Facts       []string // fact_ids of the policy statements that produced the allow (provenance)
}

// Evaluate answers: can principalArn perform action on resourceArn? It follows
// AWS's evaluation order:
//
//	explicit DENY wins -> SCP must allow -> boundary must allow ->
//	same-account: identity OR resource allow ; cross-account: identity AND resource allow
func (s *Store) Evaluate(principalArn, action, resourceArn string) Decision {
	ctx := s.contextFor(principalArn)
	principalAcct := policy.AccountOf(principalArn)
	resourceAcct := policy.AccountOf(resourceArn)
	sameAccount := resourceAcct == "" || principalAcct == "" || principalAcct == resourceAcct

	idStmts := s.identityStatements(principalArn)

	// 1. Explicit deny anywhere (identity, resource, SCP, boundary) — deny wins.
	var condDeny bool
	var condStrs []string
	for _, set := range s.allStatementSetsFor(principalArn, resourceArn) {
		hard, cond, cs := explicitDeny(set.stmts, action, resourceArn, set.forPrincipal, principalArn, ctx)
		if hard {
			return Decision{Allowed: false}
		}
		if cond {
			condDeny = true
			condStrs = append(condStrs, cs...)
		}
	}

	// 2. SCP guardrail: if the account has SCPs, at least one must ALLOW the action.
	if scps := s.scpsFor(principalAcct); len(scps) > 0 {
		if !scpAllows(scps, action) {
			return Decision{Allowed: false}
		}
	}

	// 3. Permission boundary (if present) must ALLOW.
	if b := s.boundary(principalArn); b != nil {
		bAllow, _, _, _ := allowedBy(b.Statements, action, resourceArn, false, "", ctx)
		if !bAllow {
			return Decision{Allowed: false}
		}
	}

	// 4. Identity allow.
	idAllow, idCond, idCS, idFacts := allowedBy(idStmts, action, resourceArn, false, "", ctx)

	// KMS is special: the KEY POLICY must authorize, not just IAM. A grant gated by
	// kms:ViaService is service-mediated (the service decrypts on your behalf), NOT
	// direct principal access — so it must not create a direct CanDecrypt edge.
	if strings.HasPrefix(strings.ToLower(action), "kms:") {
		return s.evaluateKMS(principalArn, action, resourceArn, idAllow, idCond, idFacts, ctx)
	}

	// 5. Resource allow (principal named in the resource policy).
	var resAllow, resCond bool
	var resCS, resFacts []string
	if rp := s.resourcePolicy(resourceArn); rp != nil {
		resAllow, resCond, resCS, resFacts = allowedBy(rp.Statements, action, resourceArn, true, principalArn, ctx)
	}

	var allowed bool
	var via string
	if sameAccount {
		allowed = idAllow || resAllow
		switch {
		case idAllow && resAllow:
			via = "identity+resource"
		case idAllow:
			via = "identity"
		case resAllow:
			via = "resource"
		}
	} else {
		allowed = idAllow && resAllow // cross-account requires BOTH sides
		via = "identity+resource"
	}

	if !allowed {
		return Decision{Allowed: false}
	}

	conditional := condDeny
	var conds []string
	conds = append(conds, condStrs...)
	if via == "identity" || via == "identity+resource" {
		if idCond {
			conditional = true
			conds = append(conds, idCS...)
		}
	}
	if via == "resource" || via == "identity+resource" {
		if resCond {
			conditional = true
			conds = append(conds, resCS...)
		}
	}
	// provenance: the facts behind whichever side(s) granted the allow.
	var facts []string
	if via == "identity" || via == "identity+resource" {
		facts = append(facts, idFacts...)
	}
	if via == "resource" || via == "identity+resource" {
		facts = append(facts, resFacts...)
	}
	return Decision{Allowed: true, Conditional: conditional, Conditions: dedupe(conds), Via: via, Facts: dedupe(facts)}
}

type stmtSet struct {
	stmts        []policy.Statement
	forPrincipal bool // resource-based (principal is matched inside the statement)
}

func (s *Store) allStatementSetsFor(principalArn, resourceArn string) []stmtSet {
	sets := []stmtSet{{stmts: s.identityStatements(principalArn), forPrincipal: false}}
	if rp := s.resourcePolicy(resourceArn); rp != nil {
		sets = append(sets, stmtSet{stmts: rp.Statements, forPrincipal: true})
	}
	if b := s.boundary(principalArn); b != nil {
		sets = append(sets, stmtSet{stmts: b.Statements, forPrincipal: false})
	}
	for _, scp := range s.scpsFor(policy.AccountOf(principalArn)) {
		sets = append(sets, stmtSet{stmts: scp.Statements, forPrincipal: false})
	}
	return sets
}

// allowedBy reports whether a statement set Allows (action,resource). If matchPrincipal
// is set (resource policy), the statement's Principal must include principalArn.
// Returns (allow, conditional, unresolvedConditionStrings, facts) where facts are the
// fact_ids of the statements that produced the allow (provenance for the emitted edge).
func allowedBy(stmts []policy.Statement, action, resource string, matchPrincipal bool, principalArn string, ctx policy.EvalContext) (bool, bool, []string, []string) {
	var conditional bool
	var conds, solidFacts, condFacts []string
	solid := false
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		// A resource-policy ALLOW only grants directly when it names the principal
		// (or is public "*"). Principal: <account>:root is DELEGATION to IAM — it does
		// not grant a principal on its own (the identity policy must allow), so it is
		// NOT a standalone resource grant. (Denies still match broadly — see explicitDeny.)
		if matchPrincipal && !namesPrincipalDirectly(st, principalArn) {
			continue
		}
		if !actionMatches(st, action) || !resourceMatches(st, resource) {
			continue
		}
		switch policy.EvalCondition(st.Condition, ctx) {
		case policy.TriTrue:
			solid = true
			if st.Source != "" {
				solidFacts = appendUniqStr(solidFacts, st.Source)
			}
		case policy.TriUnresolved:
			conditional = true
			conds = append(conds, condLabels(st.Condition)...)
			if st.Source != "" {
				condFacts = appendUniqStr(condFacts, st.Source)
			}
		}
	}
	if solid {
		return true, false, nil, solidFacts // a solid allow: its facts are the grants
	}
	if conditional {
		return true, true, conds, condFacts // only conditional allows found
	}
	return false, false, nil, nil
}

func appendUniqStr(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// explicitDeny reports a matching Deny. Hard deny = matched with a resolved-true
// (or absent) condition. Conditional deny = matched but condition unresolved.
func explicitDeny(stmts []policy.Statement, action, resource string, matchPrincipal bool, principalArn string, ctx policy.EvalContext) (hard, cond bool, conds []string) {
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "Deny") {
			continue
		}
		if matchPrincipal && !principalMatches(st, principalArn) {
			continue
		}
		if !actionMatches(st, action) || !resourceMatches(st, resource) {
			continue
		}
		switch policy.EvalCondition(st.Condition, ctx) {
		case policy.TriTrue:
			return true, false, nil
		case policy.TriUnresolved:
			cond = true
			conds = append(conds, condLabels(st.Condition)...)
		}
	}
	return false, cond, conds
}

// scpAllows: an SCP set allows an action if some statement Allows it (SCPs are
// permission filters; Resource is typically "*"). Deny handled in explicitDeny.
func scpAllows(scps []*policy.Document, action string) bool {
	for _, d := range scps {
		for _, st := range d.Statements {
			if strings.EqualFold(st.Effect, "Allow") && actionMatches(st, action) {
				return true
			}
		}
	}
	return false
}

// --- statement matching helpers ---

func actionMatches(st policy.Statement, action string) bool {
	if len(st.NotAction) > 0 {
		for _, p := range st.NotAction {
			if policy.MatchAction(p, action) {
				return false
			}
		}
		return true
	}
	for _, p := range st.Action {
		if policy.MatchAction(p, action) {
			return true
		}
	}
	return false
}

func resourceMatches(st policy.Statement, resource string) bool {
	if len(st.NotResource) > 0 {
		for _, p := range st.NotResource {
			if policy.MatchResource(p, resource) {
				return false
			}
		}
		return true
	}
	if len(st.Resource) == 0 {
		// resource-based policies often omit Resource (implicitly "this resource").
		return true
	}
	for _, p := range st.Resource {
		if policy.MatchResource(p, resource) {
			return true
		}
	}
	return false
}

func principalMatches(st policy.Statement, principalArn string) bool {
	if st.Principal.IsPublic() {
		return true
	}
	acct := policy.AccountOf(principalArn)
	for _, p := range st.Principal.AWSPrincipals() {
		if p == principalArn {
			return true
		}
		// account-root principal grants to every principal in that account
		if policy.AccountOf(p) == acct && (strings.HasSuffix(p, ":root") || p == acct) {
			return true
		}
		if policy.MatchResource(p, principalArn) { // wildcard principal arn
			return true
		}
	}
	return false
}

// contextFor builds the statically-known condition context for a principal.
// Keys resolvable from identity alone are populated; request-time keys are left
// absent (isRequestTimeKey marks them Unresolved -> CONDITIONAL).
func (s *Store) contextFor(principalArn string) policy.EvalContext {
	known := map[string][]string{}
	if acct := policy.AccountOf(principalArn); acct != "" {
		known["aws:PrincipalAccount"] = []string{acct}
		// kms:CallerAccount is the calling account — statically = the principal's.
		known["kms:CallerAccount"] = []string{acct}
	}
	if principalArn != "" {
		known["aws:PrincipalArn"] = []string{principalArn}
	}
	return policy.EvalContext{Known: known}
}

func condLabels(c policy.Condition) []string {
	var out []string
	for op, kv := range c {
		for k := range kv {
			out = append(out, op+":"+k)
		}
	}
	return out
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
