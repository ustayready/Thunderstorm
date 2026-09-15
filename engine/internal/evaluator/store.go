// Package evaluator computes effective IAM permissions from the bundle's policy
// facts and emits permission-derived edges. It implements AWS's real evaluation
// order (deny-wins -> SCP -> boundary -> identity/resource, cross-account both-
// sides).
package evaluator

import (
	"strings"

	"thunderstorm/engine/internal/model"
	"thunderstorm/engine/internal/policy"
)

// Store assembles, per principal, the policies that govern its permissions,
// plus resource policies and SCPs — all from bundle facts.
type Store struct {
	managed          map[string]*policy.Document   // policyArn -> parsed managed policy doc
	inline           map[string][]*policy.Document // principalArn -> inline docs
	attached         map[string][]string           // principalArn -> attached policyArns
	memberOf         map[string][]string           // userArn -> groupArns
	resourcePolicies map[string]*policy.Document   // resourceArn -> doc
	scps             map[string][]*policy.Document // account -> scp docs
	boundaries       map[string]*policy.Document   // principalArn -> permission boundary
}

// NewStore indexes all policy-bearing facts.
func NewStore(facts []model.Fact) *Store {
	s := &Store{
		managed:          map[string]*policy.Document{},
		inline:           map[string][]*policy.Document{},
		attached:         map[string][]string{},
		memberOf:         map[string][]string{},
		resourcePolicies: map[string]*policy.Document{},
		scps:             map[string][]*policy.Document{},
		boundaries:       map[string]*policy.Document{},
	}
	for _, f := range facts {
		switch f.Kind {
		case "managed_policy":
			if d := parseAttr(f, "document"); d != nil {
				s.managed[f.Source] = d
			}
		case "identity_policy":
			if d := parseAttr(f, "document"); d != nil {
				s.inline[f.Source] = append(s.inline[f.Source], d)
			}
		case "membership":
			switch f.EdgeHint {
			case "HasPolicy":
				s.attached[f.Source] = append(s.attached[f.Source], f.Target)
			case "MemberOf":
				s.memberOf[f.Source] = append(s.memberOf[f.Source], f.Target)
			}
		case "resource_policy":
			if d := parseAttr(f, "policy"); d != nil {
				s.resourcePolicies[f.Source] = d
			} else if d := parseAttr(f, "document"); d != nil {
				s.resourcePolicies[f.Source] = d
			}
		case "scp":
			if d := parseAttr(f, "document"); d != nil {
				acct := f.Scope.Account
				s.scps[acct] = append(s.scps[acct], d)
			}
		case "permission_boundary":
			if d := parseAttr(f, "document"); d != nil {
				s.boundaries[f.Source] = d
			}
		}
	}
	return s
}

// identityStatements returns the full effective identity-policy statement set for
// a principal: its inline docs + attached-managed docs + every group it belongs
// to (group inline + group attached). Deduplicated by policy arn.
func (s *Store) identityStatements(principalArn string) []policy.Statement {
	seenPolicy := map[string]bool{}
	var out []policy.Statement

	collect := func(arn string) {
		for _, d := range s.inline[arn] {
			out = append(out, d.Statements...)
		}
		for _, polArn := range s.attached[arn] {
			if seenPolicy[polArn] {
				continue
			}
			seenPolicy[polArn] = true
			if d := s.managed[polArn]; d != nil {
				out = append(out, d.Statements...)
			}
		}
	}

	collect(principalArn)
	for _, g := range s.memberOf[principalArn] {
		collect(g)
	}
	return out
}

func (s *Store) resourcePolicy(resourceArn string) *policy.Document {
	return s.resourcePolicies[resourceArn]
}

func (s *Store) scpsFor(account string) []*policy.Document {
	return s.scps[account]
}

func (s *Store) boundary(principalArn string) *policy.Document {
	return s.boundaries[principalArn]
}

func parseAttr(f model.Fact, key string) *policy.Document {
	v, ok := f.Attributes[key].(string)
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	d, err := policy.Parse(v)
	if err != nil {
		return nil
	}
	// provenance: stamp every statement with the id of the fact it came from, so an
	// allowing statement can be traced back to its policy fact during Evaluate.
	fid := model.FactID(f)
	for i := range d.Statements {
		d.Statements[i].Source = fid
	}
	return d
}
