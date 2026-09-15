package evaluator

import (
	"strings"

	"thunderstorm/engine/internal/policy"
)

// evaluateKMS implements AWS KMS's dual-authorization model, which the generic
// "identity OR resource" rule gets wrong. To use a KMS key you need the KEY POLICY
// to authorize — either:
//   - it names the principal (or "*") directly, with no kms:ViaService gate, OR
//   - it delegates to IAM via account-root ({Principal: <acct>:root, Action: kms:*})
//     AND the principal's identity policy allows the action.
//
// A statement gated by kms:ViaService only lets a SERVICE act on the caller's
// behalf (e.g. aws/secretsmanager keys) — it is NOT direct principal access, so it
// must not produce a direct CanDecrypt edge. This removes the false positives where
// every identity appeared able to decrypt every service-managed key.
func (s *Store) evaluateKMS(principalArn, action, resourceArn string, idAllow, idCond bool, idFacts []string, ctx policy.EvalContext) Decision {
	key := s.resourcePolicy(resourceArn)
	if key == nil {
		// Key policy not collected — cannot confirm the required key-side grant.
		if idAllow {
			return Decision{Allowed: true, Conditional: true, Via: "identity",
				Conditions: []string{"key_policy_unknown"}, Facts: idFacts}
		}
		return Decision{Allowed: false}
	}

	acct := policy.AccountOf(principalArn)
	var directAllow, directCond, delegatesToIAM bool
	var conds, directFacts []string
	for _, st := range key.Statements {
		if !strings.EqualFold(st.Effect, "Allow") || !actionMatches(st, action) {
			continue
		}
		if conditionHasKey(st.Condition, "kms:viaservice") {
			continue // service-mediated, not direct principal access
		}
		if namesAccountRoot(st, acct) {
			delegatesToIAM = true
		}
		if namesPrincipalDirectly(st, principalArn) {
			switch policy.EvalCondition(st.Condition, ctx) {
			case policy.TriTrue:
				directAllow = true
				if st.Source != "" {
					directFacts = appendUniqStr(directFacts, st.Source)
				}
			case policy.TriUnresolved:
				directCond = true
				conds = append(conds, condLabels(st.Condition)...)
				if st.Source != "" {
					directFacts = appendUniqStr(directFacts, st.Source)
				}
			}
		}
	}

	switch {
	case directAllow: // key policy grants the principal (or *) directly
		return Decision{Allowed: true, Via: "resource", Facts: directFacts}
	case delegatesToIAM && idAllow: // key delegates to IAM + identity allows
		return Decision{Allowed: true, Conditional: idCond, Via: "identity", Facts: idFacts}
	case directCond: // direct grant, but gated by an unresolved condition
		return Decision{Allowed: true, Conditional: true, Via: "resource", Conditions: dedupe(conds), Facts: directFacts}
	default:
		return Decision{Allowed: false}
	}
}

// conditionHasKey reports whether a condition block references a key (case-insensitive).
func conditionHasKey(c policy.Condition, key string) bool {
	for _, kv := range c {
		for k := range kv {
			if strings.EqualFold(k, key) {
				return true
			}
		}
	}
	return false
}

// namesAccountRoot reports whether a statement's Principal is the account root
// (arn:aws:iam::<acct>:root or the bare account id) — the IAM-delegation pattern.
func namesAccountRoot(st policy.Statement, acct string) bool {
	if acct == "" {
		return false
	}
	for _, p := range st.Principal.AWSPrincipals() {
		if p == acct {
			return true
		}
		if policy.AccountOf(p) == acct && strings.HasSuffix(p, ":root") {
			return true
		}
	}
	return false
}

// namesPrincipalDirectly reports whether a statement grants the specific principal
// (or is public "*"), as opposed to delegating to the account root.
func namesPrincipalDirectly(st policy.Statement, principalArn string) bool {
	if st.Principal.IsPublic() {
		return true
	}
	for _, p := range st.Principal.AWSPrincipals() {
		if strings.HasSuffix(p, ":root") {
			continue // that is delegation, not a direct grant
		}
		if p == principalArn || policy.MatchResource(p, principalArn) {
			return true
		}
	}
	return false
}
