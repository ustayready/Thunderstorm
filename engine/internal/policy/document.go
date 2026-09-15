// Package policy parses and (in M4b+) evaluates AWS IAM policy documents. M4a
// uses only the parser + principal extraction; the evaluation engine builds on
// the same Document type.
package policy

import (
	"encoding/json"
	"strings"
)

// Document is a parsed IAM policy (identity, resource, trust, SCP, or boundary).
type Document struct {
	Version    string      `json:"Version"`
	ID         string      `json:"Id,omitempty"`
	Statements []Statement `json:"Statement"`
}

// Statement is one policy statement. Action/Resource/Principal fields in AWS
// JSON may each be a string or a list (or, for Principal, a map) — the custom
// unmarshalers below normalize all forms.
type Statement struct {
	SID          string        `json:"Sid,omitempty"`
	Effect       string        `json:"Effect"` // Allow | Deny
	Action       StringOrSlice `json:"Action,omitempty"`
	NotAction    StringOrSlice `json:"NotAction,omitempty"`
	Resource     StringOrSlice `json:"Resource,omitempty"`
	NotResource  StringOrSlice `json:"NotResource,omitempty"`
	Principal    Principal     `json:"Principal,omitempty"`
	NotPrincipal Principal     `json:"NotPrincipal,omitempty"`
	Condition    Condition     `json:"Condition,omitempty"`
	Source       string        `json:"-"` // fact_id of the policy fact this statement came from (provenance)
}

// Parse unmarshals a policy document. Documents are often URL-decoded already by
// the collector; Parse also tolerates a raw JSON string.
func Parse(doc string) (*Document, error) {
	var d Document
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// StringOrSlice normalizes a JSON value that may be a single string or a list.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*s = []string{one}
	return nil
}

// Condition is a map of operator -> key -> value(s). Values normalize to slices.
type Condition map[string]map[string]StringOrSlice

// Principal represents a statement Principal. AWS allows:
//   - "*"                                  -> Wildcard=true
//   - {"AWS": "...", "Service": [...], ...} -> ByType
type Principal struct {
	Wildcard bool
	ByType   map[string][]string // "AWS" | "Service" | "Federated" | "CanonicalUser"
}

func (p *Principal) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	// "*"
	var star string
	if err := json.Unmarshal(b, &star); err == nil {
		if star == "*" {
			p.Wildcard = true
		} else {
			p.ByType = map[string][]string{"AWS": {star}}
		}
		return nil
	}
	// {"AWS": ... , "Service": ...}
	raw := map[string]StringOrSlice{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	p.ByType = map[string][]string{}
	for k, v := range raw {
		p.ByType[k] = v
		for _, one := range v {
			if one == "*" {
				p.Wildcard = true
			}
		}
	}
	return nil
}

// AWSPrincipals returns the "AWS" principals (account roots, user/role ARNs).
func (p Principal) AWSPrincipals() []string {
	if p.ByType == nil {
		return nil
	}
	return p.ByType["AWS"]
}

// IsPublic reports whether the principal grants to everyone ("*").
func (p Principal) IsPublic() bool { return p.Wildcard }

// AccountOf extracts the 12-digit account id from an ARN or account-root
// principal, or "" if none is present.
func AccountOf(arnOrPrincipal string) string {
	s := arnOrPrincipal
	if strings.HasPrefix(s, "arn:") {
		parts := strings.SplitN(s, ":", 6)
		if len(parts) >= 5 {
			return parts[4]
		}
		return ""
	}
	// bare 12-digit account id
	if len(s) == 12 && isAllDigits(s) {
		return s
	}
	return ""
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
