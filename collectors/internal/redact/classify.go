// Package redact rewrites a collected engagement.zip into a graph-isomorphic copy
// in which every organization-identifying value is replaced by a type-preserving,
// opaque, irreversible synthetic value — so the same nodes/edges/paths render with
// fake data. See docs/DESIGN-redactor.md.
package redact

import (
	"regexp"
	"strings"
)

// idType is the classification of a real identifier; it selects the fake generator.
type idType int

const (
	tOther idType = iota
	tGCPProject
	tAWSAccount
	tAzureSub
	tSAEmail
	tUserEmail // user or group email
	tDomain
	tAWSARN
	tResourceName
	tHostname
	tIP
	tCIDR
	tGUID
	tOpaqueName // a bare identifying name (tag value, displayName, owner)
)

// Ordered residual-sweep patterns. Order matters: broad/compound tokens (ARNs, emails,
// URLs) are swept before their components (accounts, domains, IPs) so we replace the
// whole identifier, not a fragment of it.
var (
	reARN      = regexp.MustCompile(`arn:[a-z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:[^\s"'\\]+`)
	reSAEmail  = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com`)
	reGSAEmail = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@(?:appspot\.gserviceaccount\.com|developer\.gserviceaccount\.com|cloudservices\.gserviceaccount\.com|[a-z0-9-]+\.gserviceaccount\.com)`)
	reEmail    = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reURL      = regexp.MustCompile(`https?://[^\s"'\\]+`)
	reCIDR     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	reIPv4     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b`)
	reGUID     = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	reAWSAcct  = regexp.MustCompile(`\b\d{12}\b`)
	reHostname = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
)

// classify infers the identifier type of a WHOLE string (exact-match classification,
// used when a field value is a single identifier). Free-text classification is handled
// by the residual sweep, not here.
func classify(s string) idType {
	s = strings.TrimSpace(s)
	if s == "" {
		return tOther
	}
	switch {
	case strings.HasPrefix(s, "arn:"):
		return tAWSARN
	case reSAEmail.MatchString(s) || reGSAEmail.MatchString(s):
		if isFullMatch(reSAEmail, s) || isFullMatch(reGSAEmail, s) {
			return tSAEmail
		}
	}
	if isFullMatch(reGUID, s) {
		return tGUID
	}
	if isFullMatch(reCIDR, s) {
		return tCIDR
	}
	if isFullMatch(reIPv4, s) || isFullMatch(reIPv6, s) {
		return tIP
	}
	if isFullMatch(reEmail, s) {
		return tUserEmail
	}
	if isFullMatch(reAWSAcct, s) {
		return tAWSAccount
	}
	if isFullMatch(reHostname, s) {
		// a dotted hostname/domain. Treat 2-label as a domain, more as a hostname.
		if strings.Count(s, ".") >= 2 {
			return tHostname
		}
		return tDomain
	}
	return tOther
}

func isFullMatch(re *regexp.Regexp, s string) bool {
	loc := re.FindStringIndex(s)
	return loc != nil && loc[0] == 0 && loc[1] == len(s)
}

// accountType picks the account-id type for a provider (drives format-preserving fakes).
func accountType(provider string) idType {
	switch provider {
	case "gcp":
		return tGCPProject
	case "azure":
		return tAzureSub
	default:
		return tAWSAccount
	}
}

// isPredefinedRole reports whether a role/policy reference is a provider-owned predefined
// role (kept verbatim — it names a capability, not a customer resource) vs a custom one.
func isPredefinedRole(s string) bool {
	// GCP predefined: "roles/<name>" with no project/org path. Custom: "projects/.../roles/..".
	if strings.HasPrefix(s, "roles/") {
		return true
	}
	// AWS managed policies are partition-owned: arn:aws:iam::aws:policy/...
	if strings.HasPrefix(s, "arn:aws:iam::aws:policy/") {
		return true
	}
	return false
}

// identifyingKeys are attribute/evidence keys whose STRING value should be faked even when
// the value doesn't self-classify as a typed identifier (bare names, owners, labels).
var identifyingKeys = map[string]bool{
	"name": true, "displayname": true, "display_name": true, "owner": true,
	"createdby": true, "created_by": true, "author": true, "principal": true,
	"description": true, "title": true, "label": true, "hostname": true,
	"dnsname": true, "dns_name": true, "fqdn": true, "username": true, "user": true,
	"email": true, "mail": true, "upn": true, "userprincipalname": true,
	"projectid": true, "project_id": true, "project": true, "account": true,
	"subscriptionid": true, "subscription_id": true, "bucket": true, "keyname": true,
}

// structuralKeys are never treated as identifying (kept verbatim regardless of value).
var structuralKeys = map[string]bool{
	"node_type": true, "type": true, "category": true, "relationship_kind": true,
	"nature": true, "state": true, "provider": true, "severity": true, "found": true,
	"emits_hint": true, "confidence": true, "weight": true, "score": true,
	"global": true, "rule_id": true, "partition": true,
}
