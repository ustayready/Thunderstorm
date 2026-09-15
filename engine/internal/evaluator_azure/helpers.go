package evaluator_azure

import (
	"strings"

	"thunderstorm/engine/internal/model"
)

// roleDefKey normalizes a role-definition id to the bare roleDefinitions/<guid> suffix.
// Assignments reference built-in roles subscription-qualified
// (/subscriptions/<sub>/providers/Microsoft.Authorization/roleDefinitions/<guid>) while the
// tenant-wide definition query returns them tenant-relative
// (/providers/Microsoft.Authorization/roleDefinitions/<guid>); normalize both sides so they link.
func roleDefKey(s string) string {
	s = strings.ToLower(s)
	if i := strings.Index(s, "/providers/microsoft.authorization/roledefinitions/"); i >= 0 {
		return s[i:]
	}
	return s
}

// networkDefaultAllow reports whether a resource's networkAcls default to Allow (no
// IP/VNet restriction) — i.e. the resource is not network-fenced.
func networkDefaultAllow(p map[string]any) bool {
	acls, ok := p["networkAcls"].(map[string]any)
	if !ok {
		return true // no ACLs configured => open by default
	}
	da, _ := acls["defaultAction"].(string)
	return da == "" || strings.EqualFold(da, "Allow")
}

// subOf extracts the subscription id from an ARM resource id (/subscriptions/<sub>/...).
func subOf(resourceID string) string {
	const p = "/subscriptions/"
	i := strings.Index(strings.ToLower(resourceID), p)
	if i < 0 {
		return ""
	}
	rest := resourceID[i+len(p):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return strings.ToLower(rest[:j])
	}
	return strings.ToLower(rest)
}

// rgScopeOf returns the /subscriptions/<sub>/resourceGroups/<rg> scope of an ARM resource
// id, or "" if it is not within a resource group.
func rgScopeOf(resourceID string) string {
	low := strings.ToLower(resourceID)
	i := strings.Index(low, "/resourcegroups/")
	if i < 0 || !strings.HasPrefix(low, "/subscriptions/") {
		return ""
	}
	rest := resourceID[i+len("/resourcegroups/"):]
	rg := rest
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rg = rest[:j]
	}
	if rg == "" {
		return ""
	}
	return resourceID[:i] + "/resourceGroups/" + rg
}

func lastSeg(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// principalIDOf returns the Entra principal (object) id a node acts as, if any: a
// user-assigned managed identity carries it in properties.principalId; a resource with
// a system-assigned identity carries it in identity.principalId.
func principalIDOf(n *model.Node) string {
	if n.Attributes == nil {
		return ""
	}
	for _, key := range []string{"properties", "identity"} {
		if m, ok := n.Attributes[key].(map[string]any); ok {
			if pid, ok := m["principalId"].(string); ok && pid != "" {
				return pid
			}
		}
	}
	return ""
}

func shortName(n *model.Node) string {
	if n == nil {
		return "?"
	}
	if n.Attributes != nil {
		if dn, ok := n.Attributes["displayName"].(string); ok && dn != "" {
			return dn
		}
	}
	a := n.ARN
	if a == "" {
		a = n.NodeID
	}
	if i := strings.LastIndexByte(a, '/'); i >= 0 {
		return a[i+1:]
	}
	return a
}

// anyMatch reports whether any Azure action pattern matches the concrete action
// (case-insensitive; `*` matches any run of characters, including `/`).
func anyMatch(patterns []string, action string) bool {
	al := strings.ToLower(action)
	for _, p := range patterns {
		if matchWildcard(strings.ToLower(p), al) {
			return true
		}
	}
	return false
}

// matchWildcard is glob matching where `*` matches any sequence (including separators).
// Azure treats a `/*/` segment as also matching zero segments (e.g. the role pattern
// `.../userAssignedIdentities/*/assign/action` grants the concrete
// `.../userAssignedIdentities/assign/action`), so we also try the collapsed form.
func matchWildcard(pattern, s string) bool {
	if matchWildcardRaw(pattern, s) {
		return true
	}
	if strings.Contains(pattern, "/*/") {
		return matchWildcardRaw(strings.ReplaceAll(pattern, "/*/", "/"), s)
	}
	return false
}

func matchWildcardRaw(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) { // first segment is a prefix
		return false
	}
	s = s[len(parts[0]):]
	// middle segments must appear in order
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}
	// last segment is a suffix ("" when the pattern ends with '*', which matches anything)
	return strings.HasSuffix(s, parts[len(parts)-1])
}
