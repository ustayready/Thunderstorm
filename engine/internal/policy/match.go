package policy

import "strings"

// MatchAction reports whether a policy action pattern (e.g. "s3:Get*", "*",
// "s3:*") matches a concrete action ("s3:GetObject"). Case-insensitive, as AWS
// treats the service:action namespace.
func MatchAction(pattern, action string) bool {
	return globMatchFold(pattern, action)
}

// MatchResource reports whether a policy resource pattern matches a concrete ARN.
// "*" matches everything. Wildcards `*` and `?` are honored. Matching is
// case-sensitive for the resource portion (ARNs are), which mirrors AWS.
func MatchResource(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	return globMatch(pattern, arn)
}

// ExpandVariables substitutes IAM policy variables like ${aws:username} using the
// provided context values. Unknown variables are left as a literal that will not
// match, which is the safe (no false-allow) default. `${*}`, `${?}`, `${$}` are
// the literal-escape forms.
func ExpandVariables(pattern string, vars map[string]string) string {
	if !strings.Contains(pattern, "${") {
		return pattern
	}
	var b strings.Builder
	for i := 0; i < len(pattern); {
		if strings.HasPrefix(pattern[i:], "${") {
			end := strings.Index(pattern[i:], "}")
			if end < 0 {
				b.WriteString(pattern[i:])
				break
			}
			name := pattern[i+2 : i+end]
			switch name {
			case "*":
				b.WriteString("*")
			case "?":
				b.WriteString("?")
			case "$":
				b.WriteString("$")
			default:
				if v, ok := vars[name]; ok {
					b.WriteString(v)
				} else {
					// leave unresolved variable as an unmatchable sentinel
					b.WriteString("\x00${" + name + "}\x00")
				}
			}
			i += end + 1
			continue
		}
		b.WriteByte(pattern[i])
		i++
	}
	return b.String()
}

// globMatch implements AWS-style wildcard matching: `*` matches any sequence
// (including empty), `?` matches exactly one character. Case-sensitive.
func globMatch(pattern, s string) bool {
	return globCore(pattern, s, false)
}

// globMatchFold is globMatch, case-insensitive.
func globMatchFold(pattern, s string) bool {
	return globCore(pattern, s, true)
}

// globCore is an iterative wildcard matcher (linear-time with backtracking on
// `*`), no regex — avoids catastrophic backtracking on adversarial policies.
func globCore(pattern, s string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		s = strings.ToLower(s)
	}
	var (
		p, str       = 0, 0
		star         = -1
		strAfterStar = 0
	)
	for str < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[str]):
			p++
			str++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			strAfterStar = str
			p++
		case star >= 0:
			p = star + 1
			strAfterStar++
			str = strAfterStar
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
