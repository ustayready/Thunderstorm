package policy

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// Tri is a three-valued condition result. Unresolved means the condition depends
// on request-time context we cannot know offline (e.g. aws:SourceIp) — the caller
// turns that into a CONDITIONAL edge rather than guessing.
type Tri int

const (
	TriTrue Tri = iota
	TriFalse
	TriUnresolved
)

func (t Tri) String() string {
	switch t {
	case TriTrue:
		return "true"
	case TriFalse:
		return "false"
	default:
		return "unresolved"
	}
}

// EvalContext carries the statically-known condition-key values for a request.
// Keys we know (principal account/org/arn, resource tags) go in Known. Any key
// not in Known that is request-time-only (classified by isRequestTimeKey) yields
// TriUnresolved; a statically-knowable key that is simply absent is a real
// "not present" (handled per operator).
type EvalContext struct {
	Known map[string][]string
}

func (c EvalContext) lookup(key string) ([]string, bool) {
	if c.Known == nil {
		return nil, false
	}
	v, ok := c.Known[normalizeKey(c.Known, key)]
	return v, ok
}

// EvalCondition evaluates a whole Condition block (AND across every operator and
// key). Returns TriFalse if any clause is false, TriUnresolved if none are false
// but at least one is unresolved, else TriTrue.
func EvalCondition(cond Condition, ctx EvalContext) Tri {
	if len(cond) == 0 {
		return TriTrue
	}
	sawUnresolved := false
	for opRaw, kv := range cond {
		op, setQualifier, ifExists := parseOperator(opRaw)
		for key, vals := range kv {
			res := evalClause(op, setQualifier, ifExists, key, vals, ctx)
			switch res {
			case TriFalse:
				return TriFalse
			case TriUnresolved:
				sawUnresolved = true
			}
		}
	}
	if sawUnresolved {
		return TriUnresolved
	}
	return TriTrue
}

// evalClause evaluates one operator/key/value-set clause.
func evalClause(op string, set setQualifier, ifExists bool, key string, patterns StringOrSlice, ctx EvalContext) Tri {
	// Null operator is about presence, not value; it is always resolvable from
	// what we statically know vs. what is request-time.
	if strings.EqualFold(op, "Null") {
		return evalNull(key, patterns, ctx)
	}

	actual, present := ctx.lookup(key)
	if !present {
		// A request-time key (MFA, SourceIp, ViaService, ...) is only "absent" to our
		// static analysis — at a real request it carries a value that decides the
		// clause. Treat it as unresolved so a deny/allow gated on it stays CONDITIONAL,
		// NOT a hard verdict. This must be checked BEFORE the IfExists shortcut: the
		// ubiquitous "Deny unless aws:MultiFactorAuthPresent" statement uses
		// BoolIfExists, and passing on the absent key would hard-deny an admin's
		// ENTIRE permission set (every capability wiped) instead of marking it
		// MFA-conditional.
		if isRequestTimeKey(key) {
			return TriUnresolved
		}
		if ifExists {
			return TriTrue // genuinely-static key absent => ...IfExists passes
		}
		// statically knowable but genuinely absent: no match for value operators
		return TriFalse
	}

	// Compare actual values against patterns per the set qualifier.
	cmp := comparatorFor(op)
	if cmp == nil {
		// operator we don't model (e.g. BinaryEquals) — be honest, don't guess.
		return TriUnresolved
	}
	return applySet(set, actual, patterns, cmp)
}

// comparator returns true if a single actual value satisfies a single pattern.
type comparator func(actual, pattern string) bool

func comparatorFor(op string) comparator {
	switch op {
	case "StringEquals":
		return func(a, p string) bool { return a == p }
	case "StringNotEquals":
		return negate(func(a, p string) bool { return a == p })
	case "StringEqualsIgnoreCase":
		return func(a, p string) bool { return strings.EqualFold(a, p) }
	case "StringNotEqualsIgnoreCase":
		return negate(func(a, p string) bool { return strings.EqualFold(a, p) })
	case "StringLike":
		return func(a, p string) bool { return globMatch(p, a) }
	case "StringNotLike":
		return negate(func(a, p string) bool { return globMatch(p, a) })
	case "NumericEquals":
		return numCmp(func(a, p float64) bool { return a == p })
	case "NumericNotEquals":
		return numCmp(func(a, p float64) bool { return a != p })
	case "NumericLessThan":
		return numCmp(func(a, p float64) bool { return a < p })
	case "NumericLessThanEquals":
		return numCmp(func(a, p float64) bool { return a <= p })
	case "NumericGreaterThan":
		return numCmp(func(a, p float64) bool { return a > p })
	case "NumericGreaterThanEquals":
		return numCmp(func(a, p float64) bool { return a >= p })
	case "DateEquals":
		return dateCmp(func(a, p time.Time) bool { return a.Equal(p) })
	case "DateNotEquals":
		return dateCmp(func(a, p time.Time) bool { return !a.Equal(p) })
	case "DateLessThan":
		return dateCmp(func(a, p time.Time) bool { return a.Before(p) })
	case "DateLessThanEquals":
		return dateCmp(func(a, p time.Time) bool { return !a.After(p) })
	case "DateGreaterThan":
		return dateCmp(func(a, p time.Time) bool { return a.After(p) })
	case "DateGreaterThanEquals":
		return dateCmp(func(a, p time.Time) bool { return !a.Before(p) })
	case "Bool":
		return func(a, p string) bool { return strings.EqualFold(a, p) }
	case "IpAddress":
		return ipMatch
	case "NotIpAddress":
		return negate(ipMatch)
	case "ArnEquals", "ArnLike":
		return func(a, p string) bool { return globMatch(p, a) }
	case "ArnNotEquals", "ArnNotLike":
		return negate(func(a, p string) bool { return globMatch(p, a) })
	default:
		return nil
	}
}

// applySet combines actual values × patterns under the set qualifier.
//   - default: TRUE if ANY (actual, pattern) pair matches (AWS's default OR for
//     a multi-valued key against multiple patterns).
//   - ForAllValues: every actual value must match at least one pattern.
//   - ForAnyValue: at least one actual value matches at least one pattern.
func applySet(set setQualifier, actual []string, patterns StringOrSlice, cmp comparator) Tri {
	anyPatternMatches := func(a string) bool {
		for _, p := range patterns {
			if cmp(a, p) {
				return true
			}
		}
		return false
	}
	switch set {
	case setForAllValues:
		for _, a := range actual {
			if !anyPatternMatches(a) {
				return TriFalse
			}
		}
		return TriTrue
	case setForAnyValue:
		for _, a := range actual {
			if anyPatternMatches(a) {
				return TriTrue
			}
		}
		return TriFalse
	default:
		for _, a := range actual {
			if anyPatternMatches(a) {
				return TriTrue
			}
		}
		return TriFalse
	}
}

func evalNull(key string, patterns StringOrSlice, ctx EvalContext) Tri {
	_, present := ctx.lookup(key)
	// Null:true  => condition matches when the key is ABSENT.
	// Null:false => condition matches when the key is PRESENT.
	want := false
	for _, p := range patterns {
		if strings.EqualFold(p, "true") {
			want = true
		}
	}
	absent := !present
	if absent && !present && isRequestTimeKey(key) {
		// We can't know if a request-time key would be present.
		return TriUnresolved
	}
	if want == absent {
		return TriTrue
	}
	return TriFalse
}

// ---------------------------------------------------------------------------
// operator parsing + helpers
// ---------------------------------------------------------------------------

type setQualifier int

const (
	setDefault setQualifier = iota
	setForAllValues
	setForAnyValue
)

// parseOperator strips the ForAllValues:/ForAnyValue: prefix and IfExists suffix.
func parseOperator(op string) (base string, set setQualifier, ifExists bool) {
	set = setDefault
	if strings.HasPrefix(op, "ForAllValues:") {
		set = setForAllValues
		op = strings.TrimPrefix(op, "ForAllValues:")
	} else if strings.HasPrefix(op, "ForAnyValue:") {
		set = setForAnyValue
		op = strings.TrimPrefix(op, "ForAnyValue:")
	}
	if strings.HasSuffix(op, "IfExists") {
		ifExists = true
		op = strings.TrimSuffix(op, "IfExists")
	}
	return op, set, ifExists
}

func negate(c comparator) comparator {
	return func(a, p string) bool { return !c(a, p) }
}

func numCmp(f func(a, p float64) bool) comparator {
	return func(a, p string) bool {
		av, err1 := strconv.ParseFloat(a, 64)
		pv, err2 := strconv.ParseFloat(p, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return f(av, pv)
	}
}

func dateCmp(f func(a, p time.Time) bool) comparator {
	return func(a, p string) bool {
		at, err1 := parseDate(a)
		pt, err2 := parseDate(p)
		if err1 != nil || err2 != nil {
			return false
		}
		return f(at, pt)
	}
}

func parseDate(s string) (time.Time, error) {
	// AWS accepts ISO 8601 and epoch seconds.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), nil
	}
	return time.Time{}, strconv.ErrSyntax
}

func ipMatch(actual, pattern string) bool {
	ip := net.ParseIP(actual)
	if ip == nil {
		return false
	}
	if strings.Contains(pattern, "/") {
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}
	pip := net.ParseIP(pattern)
	return pip != nil && pip.Equal(ip)
}

// normalizeKey makes condition-key lookup case-insensitive on the key name (AWS
// treats condition key names case-insensitively).
func normalizeKey(known map[string][]string, key string) string {
	if _, ok := known[key]; ok {
		return key
	}
	for k := range known {
		if strings.EqualFold(k, key) {
			return k
		}
	}
	return key
}

// isRequestTimeKey classifies condition keys whose value only exists at request
// time and therefore cannot be resolved offline from a bundle.
func isRequestTimeKey(key string) bool {
	k := strings.ToLower(key)
	switch k {
	case "aws:sourceip",
		"aws:currenttime",
		"aws:epochtime",
		"aws:multifactorauthpresent",
		"aws:multifactorauthage",
		"aws:securetransport",
		"aws:useragent",
		"aws:referer",
		"aws:sourcevpc",
		"aws:sourcevpce",
		"aws:vpcsourceip",
		"aws:tokenissuetime",
		"aws:requestedregion",
		// service-context keys: which service/resource is making the call is only
		// known at request time. A grant gated on these is CONDITIONAL, not denied.
		"kms:viaservice",
		"kms:grantisforawsresource",
		"aws:sourcearn",
		"aws:sourceaccount",
		"aws:calledvia",
		"aws:calledviafirst",
		"aws:calledvialast",
		"aws:viaawsservice":
		return true
	}
	return false
}
