package redact

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

func sortByRealLenDesc(s []kv) {
	sort.SliceStable(s, func(i, j int) bool { return len(s[i].real) > len(s[j].real) })
}

// scrubText redacts a free-text string: exact whole-string mapping, then substitution
// of every known identifier (longest-first), then a typed residual sweep for anything that
// still looks like an identifier. Non-identifying prose passes through unchanged.
func (r *Registry) scrubText(s string) string {
	if s == "" {
		return s
	}
	if f, ok := r.m[s]; ok {
		return f
	}
	s = r.substituteKnown(s)
	s = r.sweepResidual(s)
	return s
}

func (r *Registry) substituteKnown(s string) string {
	for _, p := range r.subs {
		if strings.Contains(s, p.real) {
			s = strings.ReplaceAll(s, p.real, p.fake)
		}
	}
	return s
}

// sweepResidual replaces any residual identifier-shaped substring with a consistent fake.
// Ordered widest-first so compound tokens are consumed before their components.
func (r *Registry) sweepResidual(s string) string {
	s = r.sweep(s, reARN, tAWSARN)
	s = r.sweepURL(s)
	s = r.sweep(s, reSAEmail, tSAEmail)
	s = r.sweep(s, reGSAEmail, tSAEmail)
	s = r.sweep(s, reEmail, tUserEmail)
	s = r.sweep(s, reCIDR, tCIDR)
	s = r.sweep(s, reIPv4, tIP)
	s = r.sweep(s, reIPv6, tIP)
	s = r.sweep(s, reGUID, tGUID)
	s = r.sweep(s, reAWSAcct, tAWSAccount)
	s = r.sweep(s, reHostname, tHostname)
	return s
}

func (r *Registry) sweep(s string, re *regexp.Regexp, t idType) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		if r.isFake(m) || r.looksFake(m) || (t == tAWSARN && isPredefinedRole(m)) {
			return m
		}
		return r.Get(m, t)
	})
}

func (r *Registry) sweepURL(s string) string {
	return reURL.ReplaceAllStringFunc(s, func(m string) string {
		if r.looksFake(m) {
			return m
		}
		u, err := url.Parse(m)
		if err != nil || u.Host == "" {
			return "https://host-" + r.slug("host", m, 3) + ".example/x"
		}
		return u.Scheme + "://" + r.Get(u.Host, tHostname) + "/x"
	})
}

// looksFake reports whether a token is already one of our synthetic outputs, so the sweep
// never rewrites a fake (which would corrupt referential integrity).
func (r *Registry) looksFake(s string) bool {
	if r.isFake(s) {
		return true
	}
	for _, p := range []string{"proj-", "sa-", "user-", "dom-", "host-", "res-", "val-",
		"id-", "ip-", "cidr-", "edge-", "path-", "site-", "ref-", "node-"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return strings.HasSuffix(s, ".example") || strings.Contains(s, ".example/")
}
