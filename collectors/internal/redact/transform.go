package redact

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode"
)

// transformer applies the registry across a record tree, tracking the current provider
// (for correct account-id typing) and a per-run timestamp offset.
type transformer struct {
	*Registry
	tOffset     time.Duration
	curProvider string
}

func newTransformer(r *Registry) *transformer {
	return &transformer{Registry: r, tOffset: offsetFromSalt(r.salt)}
}

func offsetFromSalt(salt []byte) time.Duration {
	n := binary.BigEndian.Uint32(salt[:4])
	days := 30 + int(n%700) // 30..729 days into the past
	h := int(salt[4] % 24)
	return -time.Duration(days*24+h) * time.Hour
}

// ---- Pass 1: build the registry from nodes + engagement.json --------------------------

func (t *transformer) registerRecord(m map[string]any) {
	saved := t.curProvider
	if p, ok := m["provider"].(string); ok && p != "" {
		t.curProvider = p
	}
	if id, ok := m["node_id"].(string); ok {
		t.registerNodeID(id)
	}
	for k, v := range m {
		t.registerValue(strings.ToLower(k), v)
	}
	t.curProvider = saved
}

func (t *transformer) registerNodeID(id string) {
	parts := strings.SplitN(id, "|", 4)
	if len(parts) < 4 {
		return
	}
	t.Get(parts[1], accountType(parts[0]))
	if c := classify(parts[3]); c != tOther {
		t.Get(parts[3], c)
	} else {
		t.Get(parts[3], tResourceName)
	}
}

func (t *transformer) registerValue(keyHint string, v any) {
	if keyHint == "tags" || keyHint == "labels" {
		t.registerTags(v)
		return
	}
	switch x := v.(type) {
	case map[string]any:
		saved := t.curProvider
		if p, ok := x["provider"].(string); ok && p != "" {
			t.curProvider = p
		}
		for k, e := range x {
			t.registerValue(strings.ToLower(k), e)
		}
		t.curProvider = saved
	case []any:
		for _, e := range x {
			t.registerValue(keyHint, e)
		}
	case string:
		if keyHint == "tags" || keyHint == "labels" {
			return
		}
		t.registerString(keyHint, x)
	}
}

// registerTags pre-registers tag/label values so they participate in free-text scrubbing.
func (t *transformer) registerTags(v any) {
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			t.registerTags(e)
		}
	case []any:
		for _, e := range x {
			t.registerTags(e)
		}
	case string:
		if x == "" || t.looksFake(x) {
			return
		}
		if c := classify(x); c != tOther {
			t.Get(x, c)
		} else if hasLetter(x) || len(x) >= 4 {
			t.Get(x, tOpaqueName)
		}
	}
}

func (t *transformer) registerString(keyHint, s string) {
	if s == "" || structuralKeys[keyHint] || keyHint == "permissions" || t.looksFake(s) {
		return
	}
	switch keyHint {
	case "node_id", "source", "target", "resource_id", "edge_id", "path_id", "site_id",
		"value_ref", "derived_from", "edge_ids", "region", "location", "rule_id":
		return // FK/opaque/structural — handled positionally in pass 2, not registered as text
	case "account", "ident", "project", "project_id", "projectid",
		"subscription_id", "subscriptionid":
		if s != "multi" {
			t.remapAccountish(s)
		}
		return
	case "arn", "caller_arn":
		t.scrubIdentity(s)
		return
	}
	if c := classify(s); c != tOther {
		t.Get(s, c)
		return
	}
	if identifyingKeys[keyHint] && hasLetter(s) {
		t.Get(s, tOpaqueName)
	}
}

// ---- Pass 2: apply the registry to every record ---------------------------------------

func (t *transformer) transformMap(m map[string]any) map[string]any {
	saved := t.curProvider
	if p, ok := m["provider"].(string); ok && p != "" {
		t.curProvider = p
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = t.transformValue(strings.ToLower(k), v)
	}
	t.curProvider = saved
	return out
}

func (t *transformer) transformValue(keyHint string, v any) any {
	if keyHint == "tags" || keyHint == "labels" {
		return t.transformTags(v) // every tag/label VALUE is potentially identifying
	}
	switch x := v.(type) {
	case map[string]any:
		return t.transformMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = t.transformValue(keyHint, e)
		}
		return out
	case string:
		return t.transformScalar(keyHint, x)
	default:
		return v
	}
}

func (t *transformer) transformScalar(keyHint, s string) string {
	switch keyHint {
	case "node_id", "source", "target", "resource_id":
		return t.remapNodeID(s)
	case "edge_id":
		return t.Token("edge", s)
	case "path_id":
		return t.Token("path", s)
	case "site_id":
		return t.Token("site", s)
	case "value_ref":
		return t.Token("ref", s)
	case "derived_from", "edge_ids":
		return t.Token("edge", s)
	case "arn":
		return t.remapARN(s)
	case "caller_arn":
		return t.scrubIdentity(s)
	case "account", "ident", "project", "project_id", "projectid",
		"subscription_id", "subscriptionid":
		if s == "multi" || s == "" {
			return s
		}
		return t.remapAccountish(s)
	case "first_seen", "captured_at", "created_at", "timestamp":
		return t.offsetTime(s)
	case "region", "location_kind", "provider", "node_type", "type", "category",
		"relationship_kind", "nature", "state", "severity", "emits_hint", "rule_id",
		"partition", "status", "kind", "permissions":
		return s // structural — kept verbatim
	case "narrative", "conditions", "description", "location", "title", "label", "scope":
		return t.scrubText(s)
	default:
		return t.scrubValue(keyHint, s)
	}
}

// ---- field-level remappers ------------------------------------------------------------

func (t *transformer) remapNodeID(id string) string {
	parts := strings.SplitN(id, "|", 4)
	if len(parts) < 4 {
		return t.scrubText(id)
	}
	acct := t.Get(parts[1], accountType(parts[0]))
	var native string
	if c := classify(parts[3]); c != tOther {
		native = t.Get(parts[3], c)
	} else {
		native = t.Get(parts[3], tResourceName)
	}
	return parts[0] + "|" + acct + "|" + parts[2] + "|" + native
}

func (t *transformer) remapARN(s string) string {
	if strings.HasPrefix(s, "arn:") {
		return t.Get(s, tAWSARN)
	}
	return t.scrubValue("arn", s)
}

func (t *transformer) scrubIdentity(s string) string {
	if strings.HasPrefix(s, "arn:") {
		return t.Get(s, tAWSARN)
	}
	if c := classify(s); c != tOther {
		return t.Get(s, c)
	}
	return t.scrubText(s)
}

func (t *transformer) remapAccountish(s string) string {
	if t.curProvider != "" && t.curProvider != "multi" {
		return t.Get(s, accountType(t.curProvider))
	}
	if c := classify(s); c == tAWSAccount || c == tGUID {
		return t.Get(s, c)
	}
	return t.Get(s, tGCPProject)
}

func (t *transformer) scrubValue(keyHint, s string) string {
	if c := classify(s); c != tOther {
		return t.Get(s, c)
	}
	if identifyingKeys[keyHint] && hasLetter(s) && !t.looksFake(s) {
		return t.Get(s, tOpaqueName)
	}
	return t.scrubText(s)
}

func (t *transformer) offsetTime(s string) string {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts.Add(t.tOffset).UTC().Format(time.RFC3339)
		}
	}
	return s
}

// transformTags fakes every string VALUE inside a tags/labels tree (keys kept), because
// tag values are operator-supplied and frequently identifying regardless of the key name.
func (t *transformer) transformTags(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = t.transformTags(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = t.transformTags(e)
		}
		return out
	case string:
		if x == "" || t.looksFake(x) {
			return x
		}
		if c := classify(x); c != tOther {
			return t.Get(x, c)
		}
		if hasLetter(x) || len(x) >= 4 {
			return t.Get(x, tOpaqueName)
		}
		return x
	default:
		return v
	}
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
